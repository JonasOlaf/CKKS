#ifndef COMPARISON_H
#define COMPARISON_H

#include "palisade.h"
using namespace lbcrypto;

void compareOne(Ciphertext<DCRTPoly> (&encDB), Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);
void compareAll(Ciphertext<DCRTPoly> (&encDB)[512], Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);


#endif // COMPARISON_H
