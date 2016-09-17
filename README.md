FlowScope is an oscilloscope for your network traffic. It records all traffic continuously in a ring buffer and dumps specific flows to disk on trigger events.
Triggers can be packets matching a user-defined filter or an external signal.

Installation
============
1. `git submodule update --init --recursive`
2. Compile Phobos in the `phobos` submodule. Follow instructions there.
3. `cd build ; cmake .. ; make ; cd ..`
4. ./phobos/build/phobos flowscope.lua <params>

FlowScope requires gcc 5 or later. You can use

    CC=gcc-5 CXX=g++-5 cmake ..

to set the compiler if gcc 5 is not your default.


Usage
=====

Hardware Requirements
=====

1. A NIC supported by DPDK
2. A CPU with a constant and invariant TSC. All recent Intel CPUs (Nehalem or newer) require this.

