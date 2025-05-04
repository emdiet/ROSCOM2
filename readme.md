# status: component development, currently inoperable

# Welcome to ROSCOM2!
===================

version: 0.1.0

## What is ROSCOM2?

*For when Cyclone DDS and Zenoh fail you.*

ROSCOM2 is a robust standalone network bridge that supports connectivity of ROS2 nodes over complex network topologies.

The guiding principle of ROSCOM2 is: "It Just Works Out of the Box". We're pulling out all the big guns to make ROSCOM2 work wherever it can.


## Running ROSCOM2 for the first time

1) copy the binary into a directory of your choice, on device A, open a terminal, and run the binary. An `OFFER-{guid(A)}.txt` file will be created.
2) copy the binary into a directory of your choice, on device B, open a terminal, and run the binary. An `OFFER-{guid(B)}.txt` file will be created.
3) copy the `OFFER-{guid(A)}.txt` file from device A to device B, so that on device B, there is an `OFFER-{guid(A)}.txt` file and an `OFFER-{guid(B)}.txt` file.
4) On device B, an `ANSWER-{guid(A-B)}.txt` file will be created. Copy this file back to device A. On device A, you now have an `OFFER-{guid(A)}.txt` file and an `ANSWER-{guid(A-B)}.txt` file.
5) The devices should now be bridged. The terminals should show connected, and a heartbeat should be visible.


## Code

### src1 - Node.js implementation

## Roadmap

The first implementation of ROSCOM2 is in Node.js for its simplicity, ease of development, auditability, and portability. This shall serve as a reference implementation.

The next implementation will be in C++ for performance and package size, retaining the same API, and feature parity. 

FAQ
---

## Where is ROSCOM1?

ROSCOM2 is built for ROS2. ROSCOM1 does not exist, and isn't planned.



