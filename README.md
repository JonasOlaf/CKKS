# CKKS

The encrypted identification was implemented using [Palisade](https://gitlab.com/palisade/palisade-release) in C++. The security level is 128 bits. The shown implementation uses features of 32 floats and ciphertexts of 4096, but can easily be modified to other configurations.

The main.cpp file initialises the crypto context, handles timings, and calls the HE operations.

The biometric.cpp loads the biometric data and encrypts this.

The comparison.cpp handles the encrypted comparisons.

The authServer.cpp decrypts the ciphertexts into scores and performs a decision on the decrypted scores.
