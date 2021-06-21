#ifndef BIOMETRIC_H
#define BIOMETRIC_H

#include "palisade.h"
using namespace lbcrypto;

void readTemplate(int subjectID, double (&tempArray)[512]);
void setupEncDB(Ciphertext<DCRTPoly> (&encDB)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);
void setupEncProbe(Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);
void encryptTemplate(Ciphertext<DCRTPoly> &encTemplate, double (&plainTemplate)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair);

#endif // BIOMETRIC_H
