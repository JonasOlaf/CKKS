#include "comparison.h"
#include "palisade.h"
#include <iostream>

using namespace std;
using namespace lbcrypto;


void compareOne(Ciphertext<DCRTPoly> (&encTemplate), Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	//Ciphertext<DCRTPoly> cSub = cc->EvalSub(encTemplate, encProbe);
	encTemplate = cc->EvalSub(encTemplate, encProbe);
	encTemplate = cc->EvalMult(encTemplate, encTemplate);
	// RELINEARIZATION is missing
	
	Ciphertext<DCRTPoly> rotCipher = cc->EvalAtIndex(encTemplate, 1);
	
	// Can we fix the last additional rotation somehow?
	for(int i = 0; i < (n-1); i++) { // use 511 instead of 2 for real tests.
		encTemplate = cc->EvalAdd(encTemplate, rotCipher);
		rotCipher = cc->EvalAtIndex(rotCipher,1);
	}
}

// C x
void compareAll(Ciphertext<DCRTPoly> (&encDB)[4], Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	for(int i = 0; i < C; i++) { // 64 is C
		compareOne(encDB[i], encProbe, cc, keyPair);
	}
}