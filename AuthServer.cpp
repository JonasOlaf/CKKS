#include "AuthServer.h"
#include "palisade.h"
#include <iostream>

using namespace std;
using namespace lbcrypto;

// C x
void decryptAll(Ciphertext<DCRTPoly> (&encDB)[4], double (&distances)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	for(int i = 0; i < C; i++) { // Decrypt every ciphertext
		Plaintext result;
		cc->Decrypt(keyPair.secretKey, encDB[i], &result);
		result->SetLength(batchSize);
		
		for(int j = 0; j < N; j++){ // Decode ciphertext into distances
			distances[i*N+j] = real(result->GetCKKSPackedValue()[j*n]);
		}
	}
}


void decision(double (&distances)[512]) {
	double low = distances[0];
	int id = 0;
	for(int i = 1; i < 512; i++) {
		if (distances[i] < low) {
			low = distances[i];
			id = i;
		}
	}
	cout << "Identity: " << id << "\t Distance score: " << low << endl;
}
