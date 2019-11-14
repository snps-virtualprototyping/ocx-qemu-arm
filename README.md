# OpenCpuX/qemu-arm - Open Source Instruction-Set Simulation Integration Kit

## Overview

This is an adaptation of the [QEMU](https://www.qemu.org/) ARMv7 and ARMv8 
processor models to run as a core model using the 
[OpenCpuX API](https://github.com/snps-virtualprototyping/ocx). It is not 
directly based on QEMU but uses [a fork](https://github.com/snps-virtualprototyping/uncorn) 
of [Unicorn](http://www.unicorn-engine.org/) for a library-ready version of 
QEMU.

It uses the [Capstone](https://github.com/aquynh/capstone) disassembler
framework for ARMv7 and ARMv8 disassembly.

## System Requirements
* [CMake](https://cmake.org), version 3.6 or higher
* `gcc` and `g++`

## How to build

* Clone the repository and `cd` into the repository
* Initialize and update the submodules:

        git submodule init
        git submodule update --init --recursive

* Create a `BUILD` directory

        mkdir BUILD
        cd BUILD

* Run [CMake](https://cmake.org) with `gcc` and `g++` in 64bit mode, 
  then `make` to build both the test harness and the unicorn core

        CXX="g++ -m64" CC="gcc -m64" cmake ..
        make

* The module should pass the regression tests are specified by the ocx test
  harness:

        make test

        Test project ocx-qemu-arm/BUILD
            Start 1: ocx-qemu-arm
        1/1 Test #1: ocx-qemu-arm .....................   Passed    0.02 sec

        100% tests passed, 0 tests failed out of 1


* Script for maintaining multiple builds for debug/release:

        #!/bin/sh

        for build in DEBUG RELEASE; do
            mkdir -p BUILD/$build/BUILD
            cd BUILD/$build/BUILD

            export CXX="g++ -m64"
            export CC="gcc -m64"

            cmake ../../.. -DCMAKE_BUILD_TYPE=$build -DCMAKE_INSTALL_PREFIX=..
            make -j 10
            make install

            cd ../../..
        done

## Configuration Information

The following assignments are used in the QEMU ARM core:

### ``ocx::core::interrupt``

The core expects the following IRQ inputs to be indicated via
calls to ``interrupt`` with the associated ``irq`` value.
All IRQs are active high. Calling ``interrupt`` with ``irq`` 
value 4 or higher will wakeup a core blocked in a ``WFE`` or
``WFI`` instruction without delivering a specific IRQ.

| Name             | ``irq``     |
|------------------|:-----------:|
| IRQ              | 0           |
| FIQ              | 1           |
| VIRQ             | 2           |
| VFIQ             | 3           |
| wakeup events    | 4+          |

### ``ocx::env::signal``

The core indicates occurrences of counter interrupts via
calls to ``signal`` with the associated ``sigid`` value:

| Name            | ``sigid``    |
|-----------------|:------------:|
| CNTPNSIRQ       | 0            |
| CNTVIRQ         | 1            |
| CNTHPIRQ        | 2            |
| CNTPSIRQ        | 3            |

### ``ocx::env::get_param``

The core will attempt to read the following parameter values
from the environment:

| Name           | Type         | Description                          |
|----------------|--------------|--------------------------------------|
| gicv3          | bool         | Enable GICv3 support                 |

