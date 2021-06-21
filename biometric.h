#ifndef BIOMETRIC_H
#define BIOMETRIC_H

#include "palisade.h"
using namespace lbcrypto;

extern uint32_t batchSize;
extern int n;
extern int N;
extern int C;

// n x
void readTemplate(int subjectID, double (&tempArray)[32]);
// C x
void setupEncDB(Ciphertext<DCRTPoly> (&encDB)[4], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);
void setupEncProbe(Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);

#endif // BIOMETRIC_H
