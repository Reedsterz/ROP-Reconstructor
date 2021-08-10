# ROP-Reconstructor

This repository contains the code for Dynamic Forensic Techniques forRebuilding Code Reuse Attacks Payload.

For the full details, please refer to the following([paper](./paper.pdf)).

## Relevant Files
- `./Pintool.cpp`: for binary instrumentation of the program file
- `./ROP-Reconstructor.py`: to automate the reconstruction of the payload

## How to run

### Export PIN_ROOT environment variable
`export PIN_ROOT=./pintool/pin`

#### Build tool inside source directory
`make obj-intel64/PinTool.so`

### Run tool on /bin/ls executable
`${PIN_ROOT}/pin -t obj-intel64/PinTool.so -o <output> -- <program>`

### ROP-Reconstructor
`python ROP-Reconstructor.py -r <path to ROPGadget output> -f <objdump output> -i <Pintool output>`
