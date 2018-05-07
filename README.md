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

## Immediate mode without buffering/dumping

A simple test setup with synthetic traffic for quick testing can be built with two directly connected machines.

* Install FlowScope on host A und [libmoon](https://github.com/emmericp/libmoon) on host B
* Start monitoring on host A: ```./libmoon/build/libmoon lua/flowscope.lua examples/liveStatistician.lua <dev>```
* Run ```./build/libmoon examples/pktgen.lua --rate=5000 <dev>``` on host B

The `pktgen.lua` MoonGen script generates 1000 UDP flows in the subnet 10.0.0.0/16 on random ports in the range 1234 to 2234.

For a 40 Gbit XL710 NIC you should see similar output like this on the monitor host:
```
Top flows over sliding 5s window:
#       bps     pps     Flow
1 649586.24 10826.44 ipv4_5tuple{ip_a: 10.0.0.10, ip_b: 10.1.0.10, port_a: 2143, port_b: 1234, proto: udp}
2 648500.83 10808.35 ipv4_5tuple{ip_a: 10.0.0.10, ip_b: 10.1.0.10, port_a: 1950, port_b: 1234, proto: udp}
3 647902.81 10798.38 ipv4_5tuple{ip_a: 10.0.0.10, ip_b: 10.1.0.10, port_a: 2164, port_b: 1234, proto: udp}
[...]
Active flows 1000, cumulative packets 53329880 [10665976.00/s], cumulative bytes 3199792800 [639958560.00/s], took 0.00s
```

## QQ mode with Dumpers

Hardware Requirements
=====================

1. A CPU with a constant and invariant TSC. All recent Intel CPUs (Nehalem or newer) have this feature.
2. See [libmoon](https://github.com/emmericp/libmoon)
