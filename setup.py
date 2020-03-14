import setuptools

# TODO: pipenv?

with open("README.md", "r") as fh:
  long_description = fh.read()

setuptools.setup(
  name="modbusproxy", # Replace with your own username
  version="0.0.1",
  author="Geoff Bruce-Payne",
  author_email="gbrucepayne@hotmail.com",
  description="A proxy client for Modbus serial operations",
  long_description=long_description,
  long_description_content_type="text/markdown",
  # url="https://github.com/pypa/sampleproject",
  packages=setuptools.find_packages(),
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
  ],
  python_requires='>=3.6',
  install_requires=[
    'serial',
    'asyncio',
    'pyserial-asyncio',
    'pymodbus>2.0',
  ],
)
