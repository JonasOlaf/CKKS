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
	// cout << "Use 511 rotations" << endl;
	for(int i = 0; i < 511; i++) { // use 511 instead of 2 for real tests.
		encTemplate = cc->EvalAdd(encTemplate, rotCipher);
		rotCipher = cc->EvalAtIndex(rotCipher,1);
	}
}

void compareAll(Ciphertext<DCRTPoly> (&encDB)[512], Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	for(int i = 0; i < 512; i++) {
		compareOne(encDB[i], encProbe, cc, keyPair);
		cout << i << endl;
	}
}