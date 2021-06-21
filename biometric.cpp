#include "biometric.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include "palisade.h"

using namespace std;
using namespace lbcrypto;

// n x
void readTemplate(int subjectID, double (&tempArray)[32]) {
	// REMEMBER TO CHANGE PATH n x
	string s = "/Users/jonasolafsson/Documents/speciale/biometrics.nosync/small/feret32/" + to_string(subjectID) + ".txt";
	char * path = new char [s.size() + 1];
	strcpy(path, s.c_str());
	
	ifstream template1;
	template1.open(path);
	
	if (!template1) {
		cerr << "Unable to open file " + s;
		exit(1);
	}
	
	for(int i = 0; i<n; i++) {
		template1 >> tempArray[i];
	}
	template1.close();
}


// C x
void setupEncDB(Ciphertext<DCRTPoly> (&encDB)[4], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	vector<vector<double>> plainDB(C, vector<double> (4096, 0.0));
	double plain[32] = {};  //[n]x
	
	for(int i = 0; i<C; i++) { // Each cipher
		for(int j = 0; j<N; j++) { // Each subject
			readTemplate(j+i*N, plain);
			for(int k = 0; k<n; k++) { // Each feature
				plainDB[i][j*n+k] = plain[k];
			}
		}
	}
	for(int i = 0; i<C; i++) {
		Plaintext tempP = cc->MakeCKKSPackedPlaintext(plainDB[i]);
		encDB[i] = cc->Encrypt(keyPair.publicKey, tempP);
	}
}

void setupEncProbe(Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	double probe[32] = {};  // n x
	readTemplate(999, probe);
	
	vector<double> Probe(4096);
	for(int i = 0; i < n; i++) {
		for(int j = 0; j < N; j++) {
			Probe[j*n + i] = probe[i];
		}
	}
	Plaintext tempP = cc->MakeCKKSPackedPlaintext(Probe);
	encProbe = cc->Encrypt(keyPair.publicKey, tempP);
}

