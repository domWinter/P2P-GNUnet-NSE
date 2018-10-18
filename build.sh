#!/bin/bash

if ! [ -x "$(command -v python3)" ]; then
  echo 'Error: python3 is not installed.' >&2
  return
fi

if ! [ -x "$(command -v pip3)" ]; then
  echo 'Error: pip3 is not installed.' >&2
  return
fi

if ! $(python3 -c 'import venv'); then
  echo 'Error: Python library venv is not installed.' >&2
  return
fi

if ! [ -n "$(dpkg -l | grep 'python3-venv')" ]; then
  echo 'Error: python3-venv is not installed.' >&2
  return
fi

echo "Building virtual environment for libraries.."
python3 -m venv venv
source venv/bin/activate

echo "Installing pycrypto library in venv.."
pip install pycrypto

echo "Running unittest.."
python implementation/tests/tests.py

python implementation/nse.py -h
