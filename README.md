# OSA
Optimal Signatures for Audit


## Prerequisites
1. [OpenSSL](https://www.openssl.org/)
2. [FourQlib](https://github.com/microsoft/FourQlib/tree/master/FourQ_ARM)


## Build and Compile

The repository contains:
1. datagen:
    Contains utility functions to generate a set of random log entries
2. FIPOSA:
    Contains the implementation of our first scheme FIne-grained Post-audit OSA (FIPOSA).
    To build:
        Go to FourQ_64bit_and_portable folder, and exeucte: make ``make ARCH=x64``
3. SOCOSA:
    Contains the implementation of our first scheme Signer-Optimal Coarse-grained OSA (SOCOSA).
    To build:
        Go to FourQ_64bit_and_portable folder, and exeucte: make ``make ARCH=x64``

<!-- Note: Coming soon after cleaning up the codes!! -->

