#ifndef AUTHSERVER_H
#define AUTHSERVER_H

#include "palisade.h"
using namespace lbcrypto;

double decryptOne(Ciphertext<DCRTPoly> (&encTemplate), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair, uint32_t batchSize);
void decryptAll(Ciphertext<DCRTPoly> (&encDB)[512], double (&distances)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair, uint32_t batchSize);
void decision(double (&distances)[512]);

#endif // AUTHSERVER_H
