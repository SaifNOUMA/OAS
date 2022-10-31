## SOCOSLO


**SOCOSLO** implements a coarse-grained compact and optimal signature scheme for secure logging based on FourQ. It achieves the fastest signature generation by aggregating signatures per epoch to speed-up the signing time, minimize the communication overhead, and to allow batch verification at the verifier side.

<!-- ## Contents -->


## Quick start

### Building the software and executing the tests on Linux

One can quickly test a given implementation by compiling the optimized x64 implementation using assembly with GNU GCC, using the efficient endomorphisms on a machine with AVX2 support (e.g, Intel's Haswell or Skylake):

```sh
$ bash tests/socoslo.sh NUM_EPOCHS
```

To perform selective batch verification separately after generation, verifying, and distilling the signatures, one can simply run the executable file SOCOSLO-sebver as follows:
```sh
$ ./SOCOSLO_sebver
```
