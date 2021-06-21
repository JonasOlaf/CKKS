#ifndef COMPARISON_H
#define COMPARISON_H

#include "palisade.h"
using namespace lbcrypto;

extern uint32_t batchSize;
extern int n;
extern int N;
extern int C;

void compareOne(Ciphertext<DCRTPoly> (&encDB), Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);
// C x
void compareAll(Ciphertext<DCRTPoly> (&encDB)[4], Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);


#endif // COMPARISON_H
