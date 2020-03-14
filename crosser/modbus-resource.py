import json

def get(filename):
  with open(filename) as f:
    device = json.loads(f)
  return device

def validate(device, modbus_reader_version='3.0.0'):
  if device