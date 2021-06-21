#ifndef AUTHSERVER_H
#define AUTHSERVER_H

#include "palisade.h"
using namespace lbcrypto;

extern uint32_t batchSize;
extern int n;
extern int N;
extern int C;

// C x
void decryptAll(Ciphertext<DCRTPoly> (&encDB)[4], double (&distances)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);
void decision(double (&distances)[512]);

#endif // AUTHSERVER_H
