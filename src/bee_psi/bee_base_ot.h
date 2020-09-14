/*
 * baseOT.h
 *
 *  Created on: Mar 20, 2013
 *      Author: mzohner
 */

#ifndef BEE_BASEOT_H_
#define BEE_BASEOT_H_

#include "../util/typedefs.h"
#include "../util/cbitvector.h"
#include <ctime>

#include <iostream>
#include <cstring>
#include <fstream>
#include <time.h>
#include "../util/crypto/crypto.h"

class BaseOT
{
	public:
		BaseOT(crypto* crypt, field_type ftype){
            m_cCrypto = crypt; 
            m_cPKCrypto = crypt->gen_field(ftype); 
        };
		virtual ~BaseOT(){delete m_cPKCrypto; };

		// virtual void OTBaseProcessSend(uint32_t nSndVals, uint32_t nOTs, CSocket* sock, uint8_t* ret) = 0;
		// virtual void OTBaseProcessRecv(uint32_t nSndVals, uint32_t uint32_t, CBitVector& choices, CSocket* sock, uint8_t* ret) = 0;

protected:
		crypto* m_cCrypto;
		pk_crypto* m_cPKCrypto;
		//int m_nSecParam;
		//fparams m_fParams;
		//int m_nFEByteLen;

		//Big *m_BA, *m_BB, *m_BP;
		//Big *m_X, *m_Y;

		//int m_nM, m_nA, m_nB, m_nC;

		void hashReturn(uint8_t* ret, uint32_t ret_len, uint8_t* val, uint32_t val_len, uint32_t ctr) {
			m_cCrypto->hash_ctr(ret, ret_len, val, val_len, ctr);
		}
};

/*
 * Compute the Naor-Pinkas Base OTs
 */


class NaorPinkas : public BaseOT
{
	public:
	NaorPinkas(crypto* crypto, field_type ftype) : BaseOT(crypto, ftype) {};
	~NaorPinkas(){};

    /**
     * @ly
     * Receiver: conduct one times send and one times receive
     * The receiver function has to be split into three steps
    */
    void processReceiverPre(uint32_t nSndVals, uint32_t nOTs, uint32_t* fe_bytes, fe** PK_sigma, num** pK);
    void processReceiverReceive(uint32_t nSndVals, uint32_t fe_bytes, uint32_t nOTs, uint8_t* pBuf, brickexp *bc, fe** PK_sigma, CBitVector choices);
    void processReceiverSend(uint32_t nOTs, uint8_t* ret, brickexp *bc, uint32_t* fe_bytes, num** pK);

    /**
     * @ly
     * Sender: conduct one times send and one times receive
     * The sender function has to be split into three steps
    */
	void processSenderPre(uint32_t nSndVals, uint32_t* nBufSize, uint32_t* fe_bytes, num *alpha, uint8_t* pBuf, fe **pC);
	void processSenderReceive(uint32_t nSndVals, uint32_t nOTs, uint8_t* pBuf, uint32_t fe_bytes, num *alpha, uint8_t* ret, fe **pCr);
	void processSenderSend(uint32_t nSndVals, uint32_t nOTs, num *alpha, fe **pCr, fe **pC);
};

#endif /* BEE_BASEOT_H_ */
