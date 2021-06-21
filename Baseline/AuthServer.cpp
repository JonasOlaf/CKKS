#include "AuthServer.h"
#include "palisade.h"
#include <iostream>

using namespace std;
using namespace lbcrypto;

double decryptOne(Ciphertext<DCRTPoly> (&encTemplate), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair, uint32_t batchSize) {
	Plaintext result;
	cc->Decrypt(keyPair.secretKey, encTemplate, &result);
	result->SetLength(batchSize);
	
	double a = real(result->GetCKKSPackedValue()[0]);
	return a;
}

void decryptAll(Ciphertext<DCRTPoly> (&encDB)[512], double (&distances)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair, uint32_t batchSize) {
	for(int i = 0; i < 512; i++) {
		distances[i] = decryptOne(encDB[i], cc, keyPair, batchSize);
		cout << "Identity: " << i << "\t Distance: " << distances[i] << endl;
	}
}


void decision(double (&distances)[512]) {
	int low = distances[0];
	int id = 0;
	for(int i = 1; i < 512; i++) {
		if (distances[i] < low) {
			low = distances[i];
			id = i;
		}
	}
	cout << "Identity: " << id << "\t Distance score: " << low << endl;
}
