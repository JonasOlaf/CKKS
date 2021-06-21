#include "biometric.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include "palisade.h"

using namespace std;
using namespace lbcrypto;

void readTemplate(int subjectID, double (&tempArray)[512]) {
	
	string s = "/Users/jonasolafsson/Documents/speciale/biometrics.nosync/small/feret512/" + to_string(subjectID) + ".txt";
	char * path = new char [s.size() + 1];
	strcpy(path, s.c_str());
	
	ifstream template1;
	template1.open(path);
	
	if (!template1) {
		cerr << "Unable to open file " + s;
		exit(1);
	}
	
	//tempArray[511] = {};
	for(int i = 0; i<512; i++) {
		template1 >> tempArray[i];
	}
	template1.close();
}


void encryptTemplate(Ciphertext<DCRTPoly> &encTemplate, double (&plainTemplate)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
    vector<double> tmpVector (plainTemplate, plainTemplate + sizeof(plainTemplate) / sizeof(plainTemplate[0]));
    Plaintext tempP = cc->MakeCKKSPackedPlaintext(tmpVector);
    encTemplate = cc->Encrypt(keyPair.publicKey, tempP);
	//double a = real(tempP->GetCKKSPackedValue()[0]);
	//cout << a << endl;
	
}


void setupEncDB(Ciphertext<DCRTPoly> (&encDB)[512], CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	// Array to load plaintext features into
	double plainDB[512][512] = {}; // [entries in db][no. of features]
	for(int i = 0; i < 512; i++) {
		readTemplate(i, plainDB[i]);
	}
	// Encrypt them into the encDB list of ciphertexts
	for(int i = 0; i < 512; i++) {
		encryptTemplate(encDB[i], plainDB[i], cc, keyPair);
	}
}

void setupEncProbe(Ciphertext<DCRTPoly> (&encProbe), CryptoContext<DCRTPoly> &cc, LPKeyPair<DCRTPoly> &keyPair) {
	// Load probe
	double probe[512] = {};
	readTemplate(999, probe);
	// Encrypt probe
	encryptTemplate(encProbe, probe, cc, keyPair);
}

