# OSA
**Optimal Signatures for Audit (OSA)** implements cryptographic auditing tools based on FourQ, a high-security, high-performance elliptic curve that targets the 128-bit security level.
As a high level depiction, OSA provides utility and cryptographic functions for signing, verification and audit investigation of log entries. Additionally, it provides data generation functionality to generate a set of log entries.


## Prerequisites
1. [OpenSSL](https://www.openssl.org/)
2. [FourQlib](https://github.com/microsoft/FourQlib/tree/master/FourQ_ARM)


## Contents

The repository includes the following implementations:
* [`DataGen`](datagen/): contains utility functions to generate a set of random log entries
* [`FIPOSA`](fiposa/): contains the implementation of our first scheme FIne-grained Post-audit OSA (FIPOSA).
* [`SOCOSA`](socosa/): contains the implementation of our second Signer-Optimal Coarse-grained OSA (SOCOSA).



## Quick Start

One can quickly test the auditing tools by first generate a set of log entries in [](datagen/). Then, build and run the chosen variant by the following the instructions mentioned in the specific folder.

## License

**OSA** is licensed under Apache 2.0 license; see [`License`](LICENSE) for details.


## Important Note

The implementation is just for the proof of concept. There are several places in the code that were implemented INSECURELY for the sake of code readability and understanding. We are not responsible for any damages if the code is used for commercial purposes.
