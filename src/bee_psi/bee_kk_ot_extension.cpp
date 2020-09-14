/*
 * bee_kk_ot_extension.cpp
 *
 *  Created on: Sep 10, 2020
 *      Author: ly
 *  Function: 
 *      List the functions about kk-ot-extension
 *      @TODO ZiChen
 */

#include "bee_kk_ot_extension.h"

#define TRUE 1  // as in Miracl

/*
 * ---------------------------------- OT Extension Sender Part --------------------------------------
 */

void beeKkOTCompServer::initKkOTSender(uint64_t numOTs, uint32_t bitlength, CBitVector* hash_table,
		                                CBitVector* results, uint32_t* nelesinbin, CBitVector vRcv, uint32_t numThreads){
	this->m_nOTs = numOTs;
	this->m_nOutByteLength = ceil_divide(bitlength, 8);
	this->m_vHashTable = hash_table;
	this->m_vOutput = results;
	this->m_vNumEleInBin = nelesinbin;
    this->vRcv = vRcv;
}


//Initialize and start numThreads OTSenderThread
// void beeKkOTCompServer::processSenderData(uint32_t numThreads)
// {
// 	if(this->m_nOTs == 0L){
//         cerr<< "The number of input data cannot be ZERO" << endl;
//         return false;
//     }

// #ifndef BILLION_SET
// 	//TODO@ Alex: we need to compute the starting position of a bin in the hash table
// 	m_vStartingPosForBin = (uint64_t*) malloc(sizeof(uint64_t*) * m_nOTs);
// 	m_vStartingPosForBin[0] = 0L;
// 	for(uint64_t i = 1; i < m_nOTs; i++) {
// 		m_vStartingPosForBin[i] = m_vStartingPosForBin[i-1] + m_vNumEleInBin[i-1];
// 	}
// #endif

// 	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
// 	uint64_t numOTs = ceil_divide(pad_to_multiple(m_nOTs, REGISTER_BITS), numThreads);

// 	/**
// 	 * 
// 	 *  Delete the communication operations in thread, only reserve the concurrent computations
// 	 * 
// 	 **/

// 	vector<OTProcessSenderThread*> sThreads(numThreads);

// 	for(uint32_t i = 0; i < numThreads; i++) {
// 		sThreads[i] = new OTProcessSenderThread(numOTs, i， this);
// 		sThreads[i]->Start();
// 	}

// 	for(uint32_t i = 0; i < numThreads; i++) {
// 		sThreads[i]->Wait();
// 	}
// 	//increase global unique counter for when the stash is processed
// 	m_nCounter += m_nOTs;

// 	for(uint32_t i = 0; i < numThreads; i++)
// 		delete sThreads[i];

// #ifdef VERIFY_OT
// 	uint8_t finished;
// 	m_nSockets[0].Receive(&finished, 1);

// 	verifyOT(m_nOTs);
// #endif

// #ifndef BILLION_SET
// 	free(m_vStartingPosForBin);
// #endif
// 	return true;
// }


bool beeKkOTCompServer::kkOTPreSendRoutine(uint64_t myNumOTs, CBitVector vRcv, uint64_t id){
	uint64_t ot_id;
	uint64_t myStartPos = id * myNumOTs;
	uint64_t processed_ot_blocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, (uint64_t) m_nCodeWordBits));
	uint64_t processed_ots = processed_ot_blocks * m_nCodeWordBits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t ot_lim = myStartPos + myNumOTs;

	// Contains the parts of the V matrix TOOD: replace OTEXT_BLOCK_SIZE_BITS by processedOTBlocks
	CBitVector Q(m_nCodeWordBits * processed_ots);

	// Id of the OT that is currently processed
	ot_id = myStartPos;

	while( ot_id < ot_lim ) //do while there are still transfers missing
	{
		processed_ot_blocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(ot_lim-ot_id, (uint64_t) m_nCodeWordBits));
		processed_ots = processed_ot_blocks * m_nCodeWordBits;

		/**
		 * @ly
		 * Delete this step of reception operations.
		 * 
		 * **/
		// sock->Receive(vRcv.GetArr(), processed_ots * m_nCodeWordBytes);

		BuildMatrix(Q, vRcv, processed_ot_blocks, ot_id);
		Q.EklundhBitTranspose(m_nCodeWordBits, processed_ots);
 		HashValues(Q, ot_id, min(ot_lim-ot_id, processed_ots));
		ot_id += min(ot_lim-ot_id, processed_ots);
	}

	vRcv.delCBitVector();
	Q.delCBitVector();
	return TRUE;
}


void beeKkOTCompServer::BuildMatrix(CBitVector& T, CBitVector& RcvBuf, uint64_t numblocks, uint64_t ot_ctr)
{
	uint8_t* rcvbufptr = RcvBuf.GetArr();
	uint8_t* Tptr = T.GetArr();

	//Create a buffer which is used as expansion seed and which takes the ot_ctr as input
	uint8_t* ctr_buf = (uint8_t*) calloc(AES_BYTES, sizeof(uint8_t));
	memcpy(ctr_buf, &ot_ctr, sizeof(uint64_t));
	uint64_t* counter = (uint64_t*) ctr_buf;
	//uint64_t tempctr = *counter;

#ifdef AES256_HASH
	intrin_sequential_gen_rnd8(ctr_buf, tempctr, Tptr, (int) (m_nCodeWordBytes / AES_BYTES)*numblocks, (int) m_nCodeWordBits, m_vKeySeeds);

	for (uint32_t k = 0; k < m_nCodeWordBits; k++, rcvbufptr += (m_nCodeWordBytes * numblocks))	{
		if(m_nU.GetBit(k)){
			T.XORBytes(rcvbufptr, k*m_nCodeWordBytes * numblocks, m_nCodeWordBytes * numblocks);
		}
	}
#else
	for (uint32_t k = 0; k < m_nCodeWordBits; k++, rcvbufptr += (m_nCodeWordBytes * numblocks))
	{
		*counter = ot_ctr;
		//one m_nCodeWordBytes / OTEXT_BLOCK_SIZE_uint8_tS = 2, thus 2 times the number of blocks
		for(uint64_t b = 0; b < (m_nCodeWordBytes/AES_BYTES)*numblocks; b++, (*counter)++, Tptr += OTEXT_BLOCK_SIZE_BYTES) 	{
			m_cCrypto->encrypt(m_vKeySeeds + k, Tptr, ctr_buf, AES_BYTES);//MPC_AES_ENCRYPT(m_vKeySeeds + k, Tptr, ctr_buf);
		}
		if(m_nU.GetBit(k))
		{
			T.XORBytes(rcvbufptr, k*m_nCodeWordBytes * numblocks, m_nCodeWordBytes * numblocks);
		}
	}
#endif
	free(ctr_buf);
}

void beeKkOTCompServer::HashValues(CBitVector& Q,  uint64_t ot_ctr, uint64_t processedOTs)
{
	CBitVector mask(m_nCodeWordBits);

	uint8_t* code_buf = (uint8_t*) malloc(2*m_nCodeWordBytes);

	//TODO @Alex: the ele_ctr is needed to know which element in the hash table to read
	uint64_t ele_ctr = m_vStartingPosForBin[ot_ctr];

#ifdef BILLION_SET
	uint8_t* dummy_buf = (uint8_t*) malloc(max(m_nCodeWordBytes, m_nOutByteLength));
#endif

	for(uint64_t i = ot_ctr, j = 0; j<processedOTs; i++, j++)
	{
#ifdef BILLION_SET
		//TODO @Alex: this look is iterated for every element in the i-th bin. Currently, this value is fixed to 3 (for benchmark purposes). 
		//The constant 3 needs to be replaced by the number of elements in the i-th bin. 
		for(uint64_t u = 0; u < 3; u++, ele_ctr++)
#else
		for(uint64_t u = 0; u < m_vNumEleInBin[i]; u++, ele_ctr++)
#endif
		{
			//cout << "Accessing element " << ele_ctr << " and ot " << i << endl;
			mask.Copy(m_nU.GetArr(), 0, m_nCodeWordBytes);

			memset(code_buf, 0, 2*m_nCodeWordBytes);
#ifdef BILLION_SET
			//TODO @Alex: dummy_buf is the input that is used to generate a code.
			//dummy_buf needs to be replaced by a file read operation from the hash table, where the elements from the i-th bin are processed sequentially 
			code->Encode(dummy_buf, m_nN_bytes, code_buf);
#else
			code->Encode(m_vHashTable->GetArr() + ele_ctr * m_nN_bytes, m_nN_bytes, code_buf);
#endif

			mask.ANDBytes(code_buf, 0, m_nCodeWordBytes);
			mask.XORBytes(Q.GetArr() + j * m_nCodeWordBytes, m_nCodeWordBytes);

#ifdef BILLION_SET
			//TODO @Alex: dummy_buf is currently the output buffer that the hash is written to. 
			//dummy_buf needs to be replaced by a file write operation. 
			m_cCrypto->hash_ctr(dummy_buf, m_nOutByteLength, mask.GetArr(), m_nCodeWordBytes, i);
#else
			m_cCrypto->hash_ctr(m_vOutput->GetArr() + ele_ctr * m_nOutByteLength, m_nOutByteLength, mask.GetArr(), m_nCodeWordBytes, i);
#endif
		}
	}
#ifdef BILLION_SET
	free(dummy_buf);
#endif
	free(code_buf);
}


void beeKkOTCompServer::OTBaseProcessRecv(uint8_t* ret) {
	uint8_t* keybytes = (uint8_t*) malloc(this->m_nBaseOTs * this->m_cCrypto->get_aes_key_bytes());

	//Key expansion
	uint8_t* pBufIdx = ret;
	for(uint32_t i=0; i<m_nBaseOTs; i++ ) {
		memcpy(keybytes + i * m_cCrypto->get_aes_key_bytes(), pBufIdx, m_cCrypto->get_aes_key_bytes());
		pBufIdx+=m_cCrypto->get_hash_bytes();
	}

#ifdef AES256_HASH
	intrin_sequential_ks4(m_vKeySeeds, keybytes, (int) m_nBaseOTs);
#else
	InitAESKey(m_vKeySeeds, keybytes, m_nBaseOTs, m_cCrypto);
#endif

#ifdef TIMING
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif
	free(ret);
	free(keybytes);
}


/*
 * ---------------------------------- OT Extension Receiver Part --------------------------------------
 */

void beeKkOTCompClient::initKkOTReceiver(uint64_t numOTs, uint32_t bitlength, CBitVector* choices,
		CBitVector* ret, uint32_t* nelesinbin, uint32_t numThreads) {
		m_nOTs = numOTs;
		m_nOutByteLength = ceil_divide(bitlength, 8);
		m_vHashTable = choices;
		m_vOutput = ret;
		m_vNumEleInBin = nelesinbin;
};

//Initialize and start numThreads OTSenderThread
// bool beeKkOTCompClient::processReceiverData(uint32_t numThreads)
// {
// 	if(this->m_nOTs == 0L){
//         cerr<< "The number of input data cannot be ZERO" << endl;
//         return false;
//     }

// #ifndef BILLION_SET
// 	//TODO@ Alex: we need to compute the starting position of a bin in the hash table
// 	m_vStartingPosForBin = (uint64_t*) malloc(sizeof(uint64_t) * m_nOTs);
// 	m_vStartingPosForBin[0] = 0L;
// 	for(uint64_t i = 1; i < m_nOTs; i++) {
// 		m_vStartingPosForBin[i] = m_vStartingPosForBin[i-1] + m_vNumEleInBin[i-1];
// 	}
// #endif

// 	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
// 	uint64_t internal_numOTs = ceil_divide(pad_to_multiple(m_nOTs, (uint64_t) REGISTER_BITS), (uint64_t) numThreads);

// 	vector<OTProcessReceiverThread*> rThreads(numThreads); 
// 	for(uint32_t i = 0; i < numThreads; i++)
// 	{
// 		rThreads[i] = new OTProcessReceiverThread(internal_numOTs, i, this);
// 		rThreads[i]->Start();
// 	}

// 	for(uint32_t i = 0; i < numThreads; i++)
// 	{
// 		rThreads[i]->Wait();
// 	}
// 	//In case this OT object is used again for the stash, increase global unique hashing counter
// 	m_nCounter += m_nOTs;

// 	for(uint32_t i = 0; i < numThreads; i++)
// 		delete rThreads[i];

// #ifdef VERIFY_OT
// 	//Wait for the signal of the corresponding sender thread
// 	uint8_t finished = 0x01;
// 	m_nSockets[0].Send(&finished, 1);

// 	verifyOT(m_nOTs);
// #endif

// #ifndef BILLION_SET
// 	free(m_vStartingPosForBin);
// #endif
// 	return true;
// }



uint64_t beeKkOTCompClient::kkOTPreRecvRoutine(uint64_t startPos, uint64_t numOTS, uint64_t processed_ot_blocks, 
												uint64_t processed_ots, CBitVector* vSnd){
	// A temporary part of the T matrix
	CBitVector T(m_nCodeWordBits * processed_ots);
	T.Reset();

	// Stores the codes for the choice bits
	CBitVector choicecodes(m_nCodeWordBits * m_nCodeWordBits);
	choicecodes.Reset();

	processed_ot_blocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(numOTS - startPos, (uint64_t) m_nCodeWordBits));
	processed_ots = processed_ot_blocks * m_nCodeWordBits;

	BuildMatrices(T, *vSnd, processed_ot_blocks, startPos);
	GenerateChoiceCodes(choicecodes, *vSnd, startPos, min(numOTS - startPos, processed_ots));

	T.EklundhBitTranspose(m_nCodeWordBits, processed_ots);

	HashValues(T, startPos, min(numOTS - startPos, processed_ots));

	startPos+=min(numOTS - startPos, processed_ots);

	T.delCBitVector();
	choicecodes.delCBitVector();

	return startPos;
}

void beeKkOTCompClient::GenerateChoiceCodes(CBitVector& choicecodes, CBitVector& vSnd, uint64_t ot_id, uint64_t ot_len) {
	uint32_t tmpchoice;

	uint32_t ncolumnsbyte = ceil_divide(ot_len, m_nCodeWordBits) * m_nCodeWordBytes;
	uint8_t* code_buf = (uint8_t*) malloc(2*m_nCodeWordBytes);

#ifdef BILLION_SET
	uint8_t* dummy_buf = (uint8_t*) malloc(m_nN_bytes);
#endif

	for(uint32_t block_id = 0; block_id < ot_len; block_id+=m_nCodeWordBits) {
		choicecodes.Reset();

		for(uint32_t j = 0; j < min(ot_len - block_id, (uint64_t) m_nCodeWordBits); j++, ot_id++) {
			//tmpchoice = m_nChoices.Get<uint32_t>(otid * 8, 8);
			memset(code_buf, 0, 2*m_nCodeWordBytes);
#ifdef BILLION_SET
			//TODO @Alex: dummy_buf is the input that is used to generate a code.
			//dummy_buf needs to be replaced by a file read operation from the hash table, where the elements from the i-th bin are processed sequentially 
			code->Encode(dummy_buf, m_nN_bytes, code_buf);
#else
			code->Encode(m_vHashTable->GetArr() + ot_id * m_nN_bytes, m_nN_bytes, code_buf);
#endif
			choicecodes.SetBytes(code_buf, j*m_nCodeWordBytes, m_nCodeWordBytes);
		}

		choicecodes.EklundhBitTranspose(m_nCodeWordBits, m_nCodeWordBits);

		for(uint32_t j = 0; j < m_nCodeWordBits; j++) {
			vSnd.XORBytes(choicecodes.GetArr() + j * m_nCodeWordBytes, (block_id >> 3) + j * ncolumnsbyte, m_nCodeWordBytes);
		}
	}
#ifdef BILLION_SET
	free(dummy_buf);
#endif
	free(code_buf);
}



void beeKkOTCompClient::BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint64_t numblocks, uint64_t ot_ctr)
{
	uint8_t* Tptr = T.GetArr();
	uint8_t* sndbufptr = SndBuf.GetArr();

	//Create a buffer which is used as expansion seed and which takes the ot_ctr as input
	uint8_t* ctr_buf = (uint8_t*) calloc(AES_BYTES, sizeof(uint8_t));
	memcpy(ctr_buf, &ot_ctr, sizeof(uint64_t));
	uint64_t* counter = (uint64_t*) ctr_buf;
	uint64_t tempctr = *counter;

#ifdef AES256_HASH
	//first prg output written to tptr
	intrin_sequential_gen_rnd8(ctr_buf, tempctr, Tptr, (int) (m_nCodeWordBytes / AES_BYTES)*numblocks, (int) m_nCodeWordBits, m_vKeySeedMtx);

	//second prg output written to snd buffer
	intrin_sequential_gen_rnd8(ctr_buf, tempctr, sndbufptr, (int) (m_nCodeWordBytes / AES_BYTES)*numblocks, (int) m_nCodeWordBits, m_vKeySeedMtx+m_nCodeWordBits);

#else
	for(uint32_t k = 0; k < m_nCodeWordBits; k++)
	{
		(*counter) = tempctr;
		for(uint64_t b = 0; b < numblocks*(m_nCodeWordBytes / AES_BYTES); b++, (*counter)++)
		{
			m_cCrypto->encrypt(m_vKeySeedMtx + 2*k, Tptr, ctr_buf, AES_BYTES);
			Tptr+=OTEXT_BLOCK_SIZE_BYTES;

			m_cCrypto->encrypt(m_vKeySeedMtx + 2*k + 1, sndbufptr, ctr_buf, AES_BYTES);
			sndbufptr+=OTEXT_BLOCK_SIZE_BYTES;
		}
	}
#endif
	SndBuf.XORBytes(T.GetArr(), (uint64_t) 0, m_nCodeWordBytes*numblocks*m_nCodeWordBits);
}


void beeKkOTCompClient::HashValues(CBitVector& T, uint64_t ctr, uint64_t processedOTs)
{
	uint8_t* Tptr = T.GetArr();

	//dummy buffer into which the output is written in case the bin is empty
	uint8_t* dummy_buf = (uint8_t*) malloc(m_nOutByteLength);

	for(uint64_t i = ctr; i < ctr+processedOTs; i++, Tptr+=m_nCodeWordBytes)
	{
		//TODO @Alex: the client only neesd to write the output mask of an element in bin i, if there is an actual element in bin i. 
		//In case there is an element, the output needs to be written into the output file
#ifndef BILLION_SET
		if(m_vNumEleInBin[i] > 0)
			m_cCrypto->hash_ctr(m_vOutput->GetArr() + m_vStartingPosForBin[i] * m_nOutByteLength, m_nOutByteLength, Tptr, m_nCodeWordBytes, i);
		 else
#endif
			m_cCrypto->hash_ctr(dummy_buf, m_nOutByteLength, Tptr, m_nCodeWordBytes, i);

	}
	free(dummy_buf);
}


void beeKkOTCompClient::NPBaseOTSend(uint8_t *ret) {
	uint8_t* keybytes = (uint8_t*) malloc(m_cCrypto->get_aes_key_bytes() * m_nBaseOTs * 2);

#ifdef AES256_HASH
	//Key expansion
	uint8_t* pBufIdx = pBuf;
	for(uint32_t i=0; i<m_nBaseOTs; i++ )
	{
		memcpy(keybytes + i * m_cCrypto->get_aes_key_bytes(), pBufIdx, m_cCrypto->get_aes_key_bytes());
		pBufIdx += m_cCrypto->get_hash_bytes();
		memcpy(keybytes + i * m_cCrypto->get_aes_key_bytes() + numbaseOTs * crypt->get_aes_key_bytes(), pBufIdx, m_cCrypto->get_aes_key_bytes());
		pBufIdx += m_cCrypto->get_hash_bytes();
	}
#else
	//Key expansion
	uint8_t* pBufIdx = ret;
	for(uint32_t i=0; i<m_nBaseOTs * 2; i++ )
	{
		memcpy(keybytes + i * m_cCrypto->get_aes_key_bytes(), pBufIdx, m_cCrypto->get_aes_key_bytes());
		pBufIdx += m_cCrypto->get_hash_bytes();
	}
#endif

#ifdef AES256_HASH
		intrin_sequential_ks4(m_vKeySeedMtx, keybytes, (int) m_nBaseOTs * 2);
#else
		InitAESKey(m_vKeySeedMtx, keybytes, m_nBaseOTs * 2, m_cCrypto);
#endif

	free(ret);
	free(keybytes);
}

