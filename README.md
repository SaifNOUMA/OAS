# OSA
**Optimal Signatures for Audit (OSA)** implements cryptographic auditing tools based on FourQ, a high-security, high-performance elliptic curve that targets the 128-bit security level.
As a high level depiction, OSA provides utility and cryptographic functions for signing, verification and audit investigation of log entries. Additionally, it provides data generation functionality to generate a set of log entries.


## Prerequisites
1. [OpenSSL](https://www.openssl.org/)
2. [FourQlib](https://github.com/microsoft/FourQlib/tree/master/FourQ_ARM)


## Contents

The repository includes the following implementations:
* [DataGen] (datagen/): contains utility functions to generate a set of random log entries
* [FIPOSA] (fiposa/): contains the implementation of our first scheme FIne-grained Post-audit OSA (FIPOSA).
* [SOCOSA] (socosa/): contains the implementation of our first scheme Signer-Optimal Coarse-grained OSA (SOCOSA).


<!-- 
1. datagen:
    Contains utility functions to generate a set of random log entries
2. FIPOSA:
    Contains the implementation of our first scheme FIne-grained Post-audit OSA (FIPOSA).
    To build:
        Go to FourQ_64bit_and_portable folder, and exeucte: make ``make ARCH=x64``
3. SOCOSA:
    Contains the implementation of our first scheme Signer-Optimal Coarse-grained OSA (SOCOSA).
    To build:
        Go to FourQ_64bit_and_portable folder, and exeucte: make ``make ARCH=x64`` -->

<!-- Note: Coming soon after cleaning up the codes!! -->

