#include <iostream>
#include "palisade.h"
#include "biometric.h"
#include "comparison.h"
#include "AuthServer.h"
#include <fstream>
#include <chrono>

using namespace std;
using namespace lbcrypto;


Ciphertext<DCRTPoly> encDB[512] = {};
Ciphertext<DCRTPoly> encProbe = {};
//int n = 512;


int main(){
	// Key generations
	uint32_t multDepth = 1;
	uint32_t scaleFactorBits = 59;
	uint32_t batchSize = 4096;

	
	SecurityLevel securityLevel = HEStd_128_classic;
	
	CryptoContext<DCRTPoly> cc =
		CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
			multDepth, scaleFactorBits, batchSize, securityLevel);
			
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	LPKeyPair<DCRTPoly> keys = cc->KeyGen();
	
	cc->EvalMultKeyGen(keys.secretKey);
	cc->EvalAtIndexKeyGen(keys.secretKey, {1,0});
	
	
	
	
	setupEncDB(encDB, cc, keys);
	setupEncProbe(encProbe, cc, keys);
	
	auto start = std::chrono::steady_clock::now();
	compareAll(encDB, encProbe, cc, keys);

	
	double distances[512] = {};
	decryptAll(encDB, distances, cc, keys, batchSize);
	decision(distances);
	
	auto end = std::chrono::steady_clock::now();
	auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end - start);
	cout << "Identification took: " << elapsed.count() << " seconds." << endl;
	
	//double result = decryptOne(encDB[1], cc, keys, batchSize);
	//cout << result << endl;
	
	
	// Debugging
	/*
	double probePtxt[512] = {};
	double temp1Ptxt[512] = {};
	readTemplate(999, probePtxt);
	readTemplate(1, temp1Ptxt);
	cout << "template:\t" << temp1Ptxt[0] << endl;
	cout << "probe:\t\t" << probePtxt[0] << endl;
	double ptxtdelta = temp1Ptxt[0] - probePtxt[0];
	cout << "plain delta:\t" << ptxtdelta<< endl;
	cout << "plain delta:\t" << ptxtdelta*ptxtdelta << endl;
	
	
	Plaintext result;
	cc->Decrypt(keys.secretKey, encDB[1], &result);
	result->SetLength(batchSize);
	
	double a = real(result->GetCKKSPackedValue()[0]);
	cout << "cipher[0]:\t" << a << endl;
	*/
	
    return 0;
}

/*
  vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
  vector<double> x2 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};

  // Encoding as plaintexts
  Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
  Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);
	vector<double> x3;
	x1.insert( x1.end(), x2.begin(), x2.end() );
  
	//vector<double> tmpVector (plainTemplate, plainTemplate + sizeof(plainTemplate) / sizeof(plainTemplate[0]));
	//Plaintext probetxt = cc->MakeCKKSPackedPlaintext(probe);
	
	//double a = real(ptxt1->GetCKKSPackedValue()[0]);
	
	cout << x1 << endl; */