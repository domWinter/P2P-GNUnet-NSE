## Peer-to-Peer - Network Size Estimation

This repository contains all development files for the network size estimation project.

---

### Reports

Reports can be found in ./reports/PDF or be generated from source in ./reports with:

```
make pdf
```
---

### Build

In order to install all required libraries in a virtual environment run:

```
source build.sh
```

---

### Tests

To run the tests simply execute:

```
python implementation/tests/tests.py
```

### Run the program

In order to run the program first start the gossip module and then execute `python nse.py` in ./implementation.


---

### Usage

```
Usage: nse.py [-h] [-c CONFIG] [-k HOSTKEY]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to config file
  -k HOSTKEY, --hostkey HOSTKEY
                        Path to hostkey file
```
