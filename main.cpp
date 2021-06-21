#include <iostream>
#include "palisade.h"
#include "biometric.h"
#include "comparison.h"
#include "AuthServer.h"
#include <fstream>
#include <chrono>
#include <vector>

using namespace std;
using namespace lbcrypto;

// C x
Ciphertext<DCRTPoly> encDB[4] = {};
Ciphertext<DCRTPoly> encProbe = {};
int n = 32;
int N = 128;
uint32_t batchSize = 4096;
int C = 4;


int main(){
	auto start = std::chrono::steady_clock::now();
	// Key generations
	uint32_t multDepth = 1;
	uint32_t scaleFactorBits = 40;

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

	auto initDone = std::chrono::steady_clock::now();
	setupEncProbe(encProbe, cc, keys);
	compareAll(encDB, encProbe, cc, keys);

	double distances[512] = {};
	decryptAll(encDB, distances, cc, keys);
	decision(distances);

	auto identificationDone = std::chrono::steady_clock::now();
	auto initTime = std::chrono::duration_cast<std::chrono::milliseconds>(initDone - start);
	auto identificationTime = std::chrono::duration_cast<std::chrono::milliseconds>(identificationDone - initDone);
	cout << "Initialisation:\t" << initTime.count() << " ms" << endl;
	cout << "Identification:\t" << identificationTime.count() << " ms"  << endl;

	return 0;
}
