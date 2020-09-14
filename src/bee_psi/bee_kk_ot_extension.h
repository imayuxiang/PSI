/*
 *  bee_kk_ot_extension.h
 *
 *  Created on: Sep 10, 2020
 *      Author: ly
 *  Function: 
 *      List the functions about kk-ot-extension
 *      @TODO ZiChen
 */

#ifndef __BEE_KK_OT_EXTENSION_
#define __BEE_KK_OT_EXTENSION_

#include "../util/typedefs.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "../util/crypto/crypto.h"
#include "../util/ecc.h"
#include "bee_base_ot.h"


//#define DEBUG_HASH_INPUT
//#define DEBUG_PRG_OUTPUT
//#define DEBUG_HASH_OUTPUT
//#define BILLION_SET


static void InitAESKey(AES_KEY_CTX* ctx, uint8_t* keybytes, uint32_t numkeys, crypto* crypt)
{
	uint8_t* pBufIdx = keybytes;
	for(uint32_t i=0; i<numkeys; i++ )
	{
		crypt->init_aes_key(ctx + i, pBufIdx);

		pBufIdx += AES_BYTES;
	}
}

/**
 * @ly
 * Here, "sender" means server plays the Sender role in OT, not means there are data required for sending
 * 
*/
class beeKkOTCompServer {

	/*
		baseOTs = 256;
		N_bits = bit length of elements in bin
		crypt = reference to crypto object (initialized with 128-bit security parameter)
		sock = socket that is used for internal communication
	*/
  public:
	beeKkOTCompServer(uint32_t baseOTs, uint32_t N_bits, crypto* crypt, CBitVector m_nU) {
		m_nBaseOTs = baseOTs;
		m_nCounter = 0L;
		m_cCrypto = crypt;
		m_nN_bytes = ceil_divide(N_bits, 8);


		//Initialize and compute the base-OTs
#ifdef AES256_HASH
		m_vKeySeeds = (ROUND_KEYS*) malloc(sizeof(ROUND_KEYS) * m_nBaseOTs);
#else
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nBaseOTs);
#endif
        m_nU = m_nU;
        // this function should be conducted seperately
		// NPBaseOTReceiver();

		//initialize the error-correcting code
		code = new ECC();
	};

	~beeKkOTCompServer(){
		free(m_vKeySeeds);
		delete code;
	};

	void OTBaseProcessRecv(uint8_t* ret);

	/*
		numOTs = number of bins
		bitlength = output bit length of masks
		hash_table = @Alex: needs to be replaced with path to file where hash table is stored
		results = @Alex: needs to be replaced with path to file where results are stored
		numThreads = number of threads that are run in parallel
		nelesinbin = array with number of elements in the i-th bin 
	*/

	void initKkOTSender(uint64_t numOTs, uint32_t bitlength, CBitVector* hash_table, CBitVector* results, 
				 	uint32_t* nelesinbin, CBitVector vRcv, uint32_t numThreads = 1);
	void processSenderData(uint32_t numThreads);

	bool kkOTPreSendRoutine(uint64_t myNumOTs, CBitVector vRcv, uint64_t id=0);
	void BuildMatrix(CBitVector& T, CBitVector& RcvBuf, uint64_t blocksize, uint64_t ctr);
	void HashValues(CBitVector& Q, uint64_t ctr, uint64_t processedOTs);

  private:
	//Sender and Receiver Common Variables
	ECC* code;
	uint64_t* m_vStartingPosForBin;
  	uint64_t m_nOTs;
  	uint64_t m_nCounter;
	uint32_t m_nN_bytes;
	uint32_t* m_vNumEleInBin;
  	uint32_t m_nBaseOTs;
  	uint32_t m_nOutByteLength;
  	CSocket* m_nSockets;
  	crypto* m_cCrypto;

  	//Sender Variables
  	CBitVector m_nU;
    CBitVector vRcv;
  	CBitVector* m_vHashTable;
  	CBitVector* m_vOutput;
#ifdef AES256_HASH
  	ROUND_KEYS* m_vKeySeeds;
#else
  	AES_KEY_CTX* m_vKeySeeds;
#endif

	class OTProcessSenderThread : public CThread {
	 	public:
	 		OTProcessSenderThread(uint64_t id, uint64_t nOTs, beeKkOTCompServer* ext) {senderID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTProcessSenderThread(){};
			void ThreadMain() {success = callback->kkOTPreSendRoutine(senderID, numOTs);};
		private: 
			uint64_t senderID;
			uint64_t numOTs;
			beeKkOTCompServer* callback;
			bool success;
	};

};



class beeKkOTCompClient {
/*
 * OT receiver part
 * Input: 
 * nSndVals: perform a 1-out-of-nSndVals OT
 * nOTs: the number of OTs that shall be performed
 * choices: a vector containing nBaseOTs choices in the domain 0-(SndVals-1) 
 * ret: returns the resulting bit representations, Has to initialized to a byte size of: nOTs * state.field_size
 * 
 * Output: was the execution successful?
 */

  public:

	/*
		baseOTs = 256;
		N_bits = bit length of elements in bin
		crypt = reference to crypto object (initialized with 128-bit security parameter)
		sock = socket that is used for internal communication
	*/

	beeKkOTCompClient(uint32_t baseOTs, uint32_t N_bits, crypto* crypt)  {
		m_nBaseOTs = baseOTs;
		m_cCrypto = crypt;
		m_nCounter = 0L;
		m_nN_bytes = ceil_divide(N_bits, 8);


		//Initialize and compute the base-OTs
#ifdef AES256_HASH
		m_vKeySeedMtx = (ROUND_KEYS*) malloc(sizeof(ROUND_KEYS) * m_nBaseOTs * 2);
#else
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nBaseOTs * 2);
#endif
		// NPBaseOTSender();

		//Initialize the error-correcting code routines
		code = new ECC();
	};

	~beeKkOTCompClient() {
		free(m_vKeySeedMtx);
		delete code;
	};

	void NPBaseOTSend(uint8_t *ret);

	/*
		numOTs = number of bins
		bitlength = output bit length of masks
		choices = @Alex: needs to be replaced with path to file where hash table is stored
		ret = @Alex: needs to be replaced with path to file where results are stored
		numThreads = number of threads that are run in parallel
		nelesinbin = array with number of elements in the i-th bin (for the receiver either 0 or 1). 
	*/
	void initKkOTReceiver(uint64_t numOTs, uint32_t bitlength, CBitVector* choices,
		CBitVector* ret, uint32_t* nelesinbin, uint32_t numThreads=1);
	bool processReceiverData(uint32_t numThreads);

	uint64_t kkOTPreRecvRoutine(uint64_t startPos, uint64_t numOTS, uint64_t processed_ot_blocks, 
									uint64_t processed_ots, CBitVector* vSnd);
	void GenerateChoiceCodes(CBitVector& choicecodes, CBitVector& vSnd, uint64_t ctr, uint64_t lim);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint64_t numblocks, uint64_t ctr);
	void HashValues(CBitVector& T, uint64_t ctr, uint64_t lim);


  private:
	//Sender and Receiver Common Variables
	ECC* code;
  	uint64_t m_nOTs;
  	uint64_t m_nCounter;
	uint64_t* m_vStartingPosForBin;
	uint32_t m_nN_bytes;
	uint32_t* m_vNumEleInBin;
  	uint32_t m_nBaseOTs;
  	uint32_t m_nOutByteLength;
  	CSocket* m_nSockets;
  	crypto* m_cCrypto;


  	//Receiver Variables
  	CBitVector* m_vHashTable;
  	CBitVector* m_vOutput;

#ifdef AES256_HASH
  	ROUND_KEYS* m_vKeySeedMtx;
#else
  	AES_KEY_CTX* m_vKeySeedMtx;
#endif

	// class OTProcessReceiverThread : public CThread {
	//  	public:
	//  		OTProcessReceiverThread(uint64_t id, uint64_t nOTs, beeKkOTCompClient* ext) {receiverID = id; numOTs = nOTs; callback = ext; success = false;};
	//  		~OTProcessReceiverThread(){};
	// 		void ThreadMain() {success = callback->kkOTPreRecvRoutine(receiverID, numOTs);};
	// 	private: 
	// 		uint64_t receiverID;
	// 		uint64_t numOTs;
	// 		beeKkOTCompClient* callback;
	// 		bool success;
	// };

};

#endif //__BEE_KK_OT_EXTENSION_
