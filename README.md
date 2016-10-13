FlowScope is an oscilloscope for your network traffic. It records all traffic continuously in a ring buffer and dumps specific flows to disk on trigger events.
Triggers can be packets matching a user-defined filter or an external signal.

Installation
============
1. `git submodule update --init --recursive`
2. Compile libmoon in the `libmoon` submodule. Follow instructions there.
3. `cd build ; cmake .. ; make ; cd ..`
4. `./libmoon/build/libmoon flowscope.lua --help`

FlowScope requires gcc 5 or later. You can use

    CC=gcc-5 CXX=g++-5 cmake ..

to set the compiler if gcc 5 is not your default.

Usage
=====

A simple test setup with synthetic traffic for quick testing can be built with two directly connected machines.

* Install FlowScope on host A und [MoonGen](https://github.com/emmericp/MoonGen) on host B
* Clone our [test repo](https://github.com/emmericp/flowscope-tests) containing MoonGen scripts on host B
* Run `sudo ./libmoon/build/libmoon flowscope.lua 0 --trigger-expr 'udp port 60000' --dumper-expr 'host $srcIP'` on host A
* Run `sudo /path/to/MoonGen/build/MoonGen test-high-background-traffic.lua 0 -t 4` on host B

The `test-high-background-traffic.lua` MoonGen script generates a lot of random flows in the subnet 10.0.0.0/16 on random ports in the range 1000 to 10000.
One of these IPs will generate a single packet to UDP port 60000 after a configurable delay (`-t 4`), this triggers FlowScope and all traffic from this IP is dumped.
You can also run the packet generator more than once in a single session to take multiple captures.
Run any of the example scripts (or FlowScope itself) with `-h` for further options.

You can also manually trigger FlowScope by sending `SIGUSR1` to the process. This can be used to integrate external monitoring systems.


Hardware Requirements
=====================

1. A NIC supported by DPDK
2. A CPU with a constant and invariant TSC. All recent Intel CPUs (Nehalem or newer) have this feature.

