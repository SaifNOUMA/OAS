## FIPOSLO


**FIPOSLO** implements a fine-grained signature-based secure logging scheme based on FourQ. It keeps all signatures separately at the verifier side to be verified individually.
This enable the highest level of granularity with a constant public key size. FIPOSLO exploits BPV precomputation technique [1] to amortize the signature generation for low-end devices in IoT. After distilling the authentication tags by keeping the invalid signatures intact while aggregating the valid ones according to a granularity parameter that we choose during the key generation process.

<!-- ## Contents -->


## Quick start

### Building the software and executing the tests on Linux

One can quickly test a given implementation by compiling the optimized x64 implementation using assembly with GNU GCC, using the efficient endomorphisms on a machine with AVX2 support (e.g, Intel's Haswell or Skylake):

```sh
$ bash tests/fiposlo.sh NUM_EPOCHS
```

To perform the selective batch verification separately after generation, verifying, and distilling the signatures, one can simply run the executable file FIPOSLO-sebver as follows:
```sh
$ ./FIPOSLO-sebver
```

# References

[1]   V. Boyko, M. Peinado, and R. Venkatesan, “Speeding up discrete log and factoring based schemes via precomputations,” in Advances in Cryptology — EUROCRYPT’98: International Conference on the Theory and Application of Cryptographic Techniques Espoo, Finland, May 31 – June 4, 1998 Proceedings, pp. 221–235.
