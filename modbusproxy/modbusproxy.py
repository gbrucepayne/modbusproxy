#!/usr/bin/env python
"""
TODO: docs
On some Linux systems you may need to: sudo usermod -a -G dialout youruser
"""

__version__ = "0.1.0"

import argparse
import time
import logging
from logging.handlers import RotatingFileHandler
import sys
import os
import glob
import serial
import asyncio
# import pymodbus
from pymodbus.client.asynchronous.serial import AsyncModbusSerialClient
from pymodbus.client.asynchronous.tcp import AsyncModbusTCPClient
from pymodbus.client.asynchronous.udp import AsyncModbusUDPClient
from pymodbus.client.asynchronous import schedulers
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder


# --------------------------------------------------------------------------- #
# Crosser.io integration
# --------------------------------------------------------------------------- #
import json
'''
# Example 2: internal looping - initialize method started on another thread
def initialize(module):
  print('initialize')
  counter = 0
  msg = {}
  while(True):
    msg['count'] = counter
    counter += 1
    module.next(msg)
    time.sleep(1)
'''
'''
# Example 3: stateful information
state = 0
count = 0
state = {'tot' : 0, 'count' : 0}
'''
def msg_handler(msg, module):
  """Intended to be triggered by an Interval Module"""
  print(json.dumps(msg))
  # pass a message to the next Crosser module
  # global device
  data = []
  # for tag in device.tags:
  #   data.append(device.report_tag(tag.id))
  module.next({'data': data})
  '''
  # Example 3: maintain stateful information
  global count
  global tot
  tot = state['tot']
  count = state['count']
  tot += msg['value']
  count += 1
  state['tot'] = tot
  state['count'] = count
  result = {'avg' : tot/count}
  module.next(result)
  '''
  '''
  # Example 4: Only call next module if value violates some thresholds
  if msg['value'] > 75:
    module.next({'message':'Value is greater than 75'})
  if msg['value'] < 25:
    module.next({'message':'Value is less than 25'})
  '''


# --------------------------------------------------------------------------- #
# Modbus function code reference
# --------------------------------------------------------------------------- #
READ_CO = 0x01
READ_DI = 0x02
READ_HR = 0x03
READ_IR = 0x04
WRITE_SINGLE_CO = 0x05
WRITE_SINGLE_HR = 0x06
WRITE_MULTI_CO = 0x0f
WRITE_MULTI_HR = 0x10
READ_EXCEPTION_STATUS = 0x07
READ_DIAGNOSTICS = 0x08


def get_wrapping_log(logfile=None, file_size=5, debug=False):
  """
  Initializes logging to console, and optionally a wrapping CSV formatted file of defined size.
  Default logging level is INFO.
  Timestamps are GMT/Zulu.

  :param logfile: the name of the file
  :param file_size: the max size of the file in megabytes, before wrapping occurs
  :param debug: Boolean to enable tick_log DEBUG logging (default INFO)
  :return: ``log`` object

  """
  FORMAT = ('%(asctime)s.%(msecs)03dZ,[%(levelname)s],(%(threadName)-10s),'
            '%(module)s.%(funcName)s:%(lineno)d,%(message)s')
  log_formatter = logging.Formatter(fmt=FORMAT,
                                    datefmt='%Y-%m-%dT%H:%M:%S')
  log_formatter.converter = time.gmtime
  if logfile is not None:
    log_object = logging.getLogger(logfile)
    log_handler = RotatingFileHandler(logfile, mode='a', 
                                      maxBytes=file_size * 1024 * 1024,
                                      backupCount=2, encoding=None, delay=0)
    log_handler.setFormatter(log_formatter)
    log_object.addHandler(log_handler)
  else:
    log_object = logging.getLogger()
  if debug:
    log_lvl = logging.DEBUG
  else:
    log_lvl = logging.INFO
  log_object.setLevel(log_lvl)
  console = logging.StreamHandler()
  console.setFormatter(log_formatter)
  console.setLevel(log_lvl)
  log_object.addHandler(console)
  return log_object


# Logger setup
log = get_wrapping_log(debug=True)


def list_serial_ports():
  """
  Lists serial port names.

  :raises EnvironmentError: On unsupported or unknown platforms
  :returns: A list of the serial ports available on the system

  """
  if sys.platform.startswith('win'):
    ports = ['COM%s' % (i + 1) for i in range(256)]
  elif sys.platform.startswith('linux') or sys.platform.startswith('cygwin'):
    # this excludes your current terminal "/dev/tty"
    ports = glob.glob('/dev/tty[A-Za-z]*')
  elif sys.platform.startswith('darwin'):
    ports = glob.glob('/dev/tty.*')
  else:
    raise EnvironmentError("Unsupported OS/platform")
  result = []
  for port in ports:
    try:
      s = serial.Serial(port)
      s.reset_input_buffer()
      s.reset_output_buffer()
      s.close()
      result.append(port)
    except serial.SerialException:
      # log.error(serial.SerialException.strerror)
      pass
  return result


class SerialPort(object):
  """
  A class to encapsulate various serial port settings as a wrapper
  for a serial.Serial object
  """
  def __init__(self, port='/dev/ttyUSB0', 
              baudrate=9600, framing='8N1'):
    if port in list_serial_ports():
      self.port = port
      self.baudrates = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200]
      self.baudrate = None
      self.databits = 8
      self.parity = serial.PARITY_NONE
      self.stopbits = 1
      self.timeout = None
      self.write_timeout = None
      self.inter_byte_timeout = None
      self.xonxoff = False
      self.rtscts = False
      self.dsrdtr = False
      self.set_baudrate(baudrate)
      self.set_framing(framing)
    else:
      raise EnvironmentError(
        "Unable to find/open specified serial port {port}".format(port=port))

  def set_baudrate(self, baudrate: int):
    if baudrate in self.baudrates:
      self.baudrate = baudrate
    else:
      raise ValueError("Invalid baudrate {}".format(baudrate))
  
  def set_framing(self, framing:str):
    if len(framing) == 3:
      databits = int(framing[0])
      parity = framing[1]
      stopbits = int(framing[2])
      if databits in [7, 8]:
        self.databits = databits
      else:
        raise ValueError("Invalid data bits {}".format(databits))
      if parity == 'N':
        self.parity = serial.PARITY_NONE
      elif parity == 'E':
        self.parity = serial.PARITY_EVEN
      elif parity == 'O':
        self.parity = serial.PARITY_ODD
      else:
        raise ValueError("Invalid parity {}".format(parity))
      if stopbits in [1, 2]:
        self.stopbits = stopbits
      else:
        raise ValueError("Invalid stop bits {}".format(stopbits))
    else:
      raise ValueError("Invalid framing {} should be of form 8N1".format(framing))


class Tag():
  """"""
  def __init__(self, register_type=None, address=None, data_type=None, 
              id=None, name=None):
    self.register_type = register_type
    self.address = address
    self.data_type = data_type
    self.length = None
    self.id = id
    self.name = name
    self.value = None


class ModbusDevice():
  """"""
  def __init__(self, resource):
    self.unit_id = 0x01
    self.co = []
    self.di = []
    self.ir = []
    self.hr = []
    self.tags = []
    self.byte_order = Endian.Big
    self.word_order = Endian.Big
    self.string_order = Endian.Big
    # TODO: fix below
    if 'unitId' in resource and (1 > resource['unitId'] >= 255):
      self.unit_id = resource['unitId']
    if 'byteOrder' in resource:
      if ('twoByte' in resource['byteOrder'] and 
          resource['byteOrder']['twoByte'] == '10'):
        self.byte_order = Endian.Little
      if ('fourByte' in resource['byteOrder'] and 
          resource['byteOrder']['fourByte'] in ['3210', '1032']):
        self.word_order = Endian.Little
      if ('string' in resource['byteOrder'] and 
          resource['byteOrder']['string'] == '10'):
        self.string_order = Endian.Little
    for t in resource['tags']:
      address = int(t['address'], 16)
      tag = Tag(address=address, data_type=t['modbusDataType'],
                id=t['id'], name=t['name'])
      if tag.data_type == 'String':
        tag.length = t['length']
      if t['modbusFunction'] == 'ReadCoils':
        self.co.append(address)
        tag.register_type = 'co'
      elif t['modbusFunction'] == 'ReadDiscreteInputs':
        self.di.append(address)
        tag.register_type = 'di'
      elif t['modbusFunction'] == 'ReadInputRegisters':
        self.ir.append(address)
        # TODO: this may not work in all cases e.g. device return 32-bit register
        if tag.data_type in ['UInt', 'Int']:
          self.ir.append(address + 1)
        tag.register_type = 'ir'
      elif t['modbusFunction'] == 'ReadHoldingRegisters':
        self.hr.append(address)
        # TODO: this may not work in all cases e.g. device return 32-bit register
        if tag.data_type in ['UInt', 'Int']:
          self.ir.append(address + 1)
        tag.register_type = 'hr'
      self.tags.append(tag)
    self.co.sort()
    self.di.sort()
    self.ir.sort()
    self.hr.sort()
  
  def get_next_register_block(self, register_type, start=0):
    if register_type == 'co':
      registers = self.co
    elif register_type == 'di':
      registers = self.di
    elif register_type == 'ir':
      registers = self.ir
    elif register_type == 'hr':
      registers = self.hr
    else:
      raise ValueError('Invalid register type must be co, di, ir, hr')
    if start in registers:
      block_start = start
    else:
      block_start = None
      for index in range(len(registers)):
        if registers[index] > start:
          block_start = registers[index]
          break
    block_end = block_start
    if block_start is not None:
      for register in registers:
        if register == block_start:
          pass
        # TODO: handle double-word values striped over 2 registers Int
        elif register == block_end + 1:
          block_end = register
        else:
          break
    return block_start, block_end

  def get_tag_id(self, register_type, address):
    for tag in self.tags:
      if tag.register_type == register_type and tag.address == address:
        return tag.id
  
  def get_tag_data_type(self, id):
    for tag in self.tags:
      if tag.id == id:
        return tag.data_type
  
  def update_tag(self, id, raw):
    for tag in self.tags:
      if tag.id == id:
        if tag.register_type in ['co', 'di']:
          tag.value = raw
        else:
          decoder = BinaryPayloadDecoder.fromRegisters(raw, 
                      byteorder=self.byte_order, wordorder=self.word_order)
          if tag.data_type == 'UShort':
            tag.value = decoder.decode_16bit_uint()
          elif tag.data_type == 'Short':
            tag.value = decoder.decode_16bit_int()
          elif tag.data_type == 'UInt':
            tag.value = decoder.decode_32bit_uint()
          elif tag.data_type == 'Int':
            tag.value = decoder.decode_32bit_int()
          elif tag.data_type == 'Float':
            tag.value = decoder.decode_32bit_float()
          elif tag.data_type == 'Byte':
            tag.value = decoder.decode_bits()
          elif tag.data_type == 'String':
            tag.value = decoder.decode_string(size=tag.length)
          else:
            raise ValueError('tag data_type undefined')
        break
  
  def report_tag(self, id):
    for tag in self.tags:
      if tag.id == id:
        return {
          'id': tag.id,
          'name': tag.name,
          'value': tag.value or 0
        }


async def polling(client, device: ModbusDevice, interval_seconds=1):
  try:
    
    log.debug("Reading Coils")
    reading_co = True
    block_start = device.co[0]
    while reading_co:
      block_start, block_end = device.get_next_register_block('co', block_start)
      if block_start is not None:
        count = block_end - block_start + 1
        result = await client.read_coils(block_start, count, unit=device.unit_id)
        if result.function_code > 0x80:
          log.error('Modbus read_coils error {}'.format(result.function_code))
        else:
          for index in range(0, count - 1):
            id = device.get_tag_id('co', block_start + index)
            device.update_tag(id, result.bits[index])
        block_start = block_end + 1
      else:
        reading_co = False
    
    log.debug("Reading Discrete Inputs")
    reading_di = True
    block_start = device.di[0]
    while reading_di:
      block_start, block_end = device.get_next_register_block('di', block_start)
      if block_start is not None:
        count = block_end - block_start + 1
        result = await client.read_discrete_inputs(block_start, count, unit=device.unit_id)
        if result.function_code > 0x80:
          log.error('Modbus read_discrete_inputs error {}'.format(result.function_code))
        else:
          for index in range(0, count - 1):
            id = device.get_tag_id('di', block_start + index)
            device.update_tag(id, result.bits[index])
        block_start = block_end + 1
      else:
        reading_di = False
    
    log.debug("Reading Input Registers")
    reading_ir = True
    block_start = device.ir[0]
    while reading_ir:
      block_start, block_end = device.get_next_register_block('ir', block_start)
      if block_start is not None:
        count = block_end - block_start + 1
        result = await client.read_input_registers(block_start, count, unit=device.unit_id)
        if result.function_code > 0x80:
          log.error('Modbus read_input_registers error {}'.format(result.function_code))
        else:
          for index in range(0, count - 1):
            id = device.get_tag_id('ir', block_start + index)
            if device.get_tag_data_type in ['UInt', 'Int', 'Float']:
              registers = result.registers[index:index+2]
            # TODO: fix for strings striped across a register block
            else:
              registers = [result.registers[index]]
            device.update_tag(id, registers)
        block_start = block_end + 1
      else:
        reading_ir = False
    
    log.debug("Reading Holding Registers")
    reading_hr = True
    block_start = device.hr[0]
    while reading_hr:
      block_start, block_end = device.get_next_register_block('hr', block_start)
      if block_start is not None:
        count = block_end - block_start + 1
        result = await client.read_holding_registers(block_start, count, unit=device.unit_id)
        if result.function_code > 0x80:
          log.error('Modbus read_holding_registers error {}'.format(result.function_code))
        else:
          for index in range(0, count - 1):
            id = device.get_tag_id('hr', block_start + index)
            if device.get_tag_data_type in ['UInt', 'Int', 'Float']:
              registers = result.registers[index:index+2]
            # TODO: fix for strings striped across a register block
            else:
              registers = [result.registers[index]]
            device.update_tag(id, registers)
        block_start = block_end + 1
      else:
        reading_hr = False
  
    data = {}
    for tag in device.tags:
      data
    
  except Exception as e:
    log.exception(e)
    client.transport.close()
  await asyncio.sleep(1)
  
  
def get_parser():
  """
  Parses the command line arguments.

  :returns: An argparse.ArgumentParser

  """
  parser = argparse.ArgumentParser(description="Modbus Slave Device.")

  port_choices = list_serial_ports() + ['tcp:502', 'udp:5020']
  if '/dev/ttyUSB0' in port_choices:
    port_default = '/dev/ttyUSB0'
  else:
    port_default = 'tcp:502'
  
  parser.add_argument('-p', '--port', dest='port', default=port_default,
                      choices=port_choices,
                      help="tcp:502, udp:5020, or a USB/serial port name")

  parser.add_argument('--host', dest='host', default=None,
                      help="IP address of slave device")

  parser.add_argument('-b', '--baud', dest='baudrate', default=9600, type=int,
                      choices=[2400, 4800, 9600, 19200, 38400, 57600, 115200],
                      help="baud rate (``int`` default 9600)", metavar="{2400..115200}")

  parser.add_argument('-f', '--framing', dest='framing', default='8N1',
                      choices=['8N1'],
                      help="serial port framing shorthand "
                      "(data bits, parity, stop bits) e.g. 8N1")

  parser.add_argument('-m', '--mode', dest='mode', default='rtu',
                      choices=['rtu', 'ascii', 'tcp'],
                      help="Modbus framing mode RTU, ASCII or TCP")

  parser.add_argument('--logfile', default=None,
                      help="the log file name with optional extension (default extension .log)")

  parser.add_argument('--logsize', type=int, default=5,
                      help="the maximum log file size, in MB (default 5 MB)")

  parser.add_argument('--resource', dest='resource', default=None,
                      help="the file/path name of the Crosser Modbus Resource JSON file")

  return parser


def main():
  parser = get_parser()
  user_options = parser.parse_args()
  filepath = os.path.join(os.path.dirname(__file__), user_options.resource)
  device = ModbusDevice(json.load(open(filepath)))
  loop = None
  if '/dev/tty' in user_options.port:
    ModbusClient = AsyncModbusSerialClient
    serial = SerialPort(user_options.port, 
                        user_options.baudrate, 
                        user_options.framing)
    loop, client = ModbusClient(schedulers.ASYNC_IO, method=user_options.mode,
                                port=serial.port, baudrate=serial.baudrate,
                                bytesize=serial.databits, parity=serial.parity,
                                stopbits=serial.stopbits,
                                # timeout=serial.timeout
                                )
  else:
    if 'tcp' in user_options.port:
      ModbusClient = AsyncModbusTCPClient
      ip_port = int(user_options.port.split(':')[1]) or 502
    elif 'udp' in user_options.port:
      ModbusClient = AsyncModbusUDPClient
      ip_port = int(user_options.port.split(':')[1]) or 5020
    loop, client = ModbusClient(schedulers.ASYNC_IO, 
                                host=user_options.host, port=ip_port)
  if loop is not None:
    loop.run_until_complete(polling(client.protocol, device))
    loop.close()
  else:
    log.error('Could not initialize modbusproxy loop')


if __name__ == '__main__':
  main()
