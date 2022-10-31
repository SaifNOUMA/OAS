# OSLO
**Optimal Signatures for Secure Logging (OSLO)** implements cryptographic secure logging tools based on FourQ, a high-security, high-performance elliptic curve that targets the 128-bit security level.
As a high level depiction, OSLO provides utility and cryptographic functions for signing, verification and investigation of log entries. Additionally, it provides data generation functionality to generate a set of log entries.


## Prerequisites
1. [OpenSSL](https://www.openssl.org/)
2. [FourQlib](https://github.com/microsoft/FourQlib/tree/master/FourQ_ARM)


## Contents

The repository includes the following implementations:
* [`DataGen`](datagen/): contains utility functions to generate a set of random log entries
* [`FIPOSLO`](fiposlo/): contains the implementation of our first scheme FIne-grained Public-key OSLO (FIPOSLO).
* [`SOCOSLO`](socoslo/): contains the implementation of our second Signer-Optimal Coarse-grained OSLO (SOCOSLO).



## Quick Start

One can quickly test the cryptographic tools by first generate a set of log entries in [`DataGen`](datagen/). Then, build and run the chosen variant by the following the instructions mentioned in the specific folder.

## License

**OSLO** is licensed under Apache 2.0 license; see [`License`](LICENSE) for details.


## Important Note

The implementation is just for the proof of concept. There are several places in the code that were implemented INSECURELY for the sake of code readability and understanding. We are not responsible for any damages if the code is used for commercial purposes.
