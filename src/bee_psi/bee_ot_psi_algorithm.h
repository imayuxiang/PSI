/*
 * bee_ot_psi_algorithm.h
 *
 *  Created on: Sep 10, 2020
 *      Author: ly
 *  Function: 
 *      List the functions about PSI algorithm.
 *      @TODO ZiChen
 */


#ifndef BEE_OT_PSI_ALGORITHM_H_
#define BEE_OT_PSI_ALGORITHM_H_

#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include "bee_kk_ot_extension.h"
#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../util/cbitvector.h"
#include "../hashing/simple_hashing.h"
#include "../hashing/cuckoo.h"
#include "../pk-based/dh-psi.h"
#include "../naive-hashing/naive-psi.h"


struct mask_rcv_ctx {
	uint8_t* rcv_buf;
	uint32_t nmasks;
	uint32_t maskbytelen;
	CSocket* sock;
};

struct query_ctx {
	GHashTable *map;
	uint8_t* result;
	uint32_t res_size;

	uint8_t* elements;
	uint32_t elebytelen;

	uint8_t* qhashes;
	uint32_t qneles;
	uint32_t hashbytelen;
};

inline crypto get_crypto_instance(uint32_t security_level){
    crypto crypto(security_level, (uint8_t*) const_seed);
    return crypto;	
}

/**
 * @Zichen
 * Functions used for SERVER
*/
void semi_ot_psi_init_server(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t pneles, uint32_t elebitlen, uint32_t maskbitlen,
		crypto* crypt_env, uint32_t ntasks, prf_state_ctx* prf_state, uint8_t* hash_table, uint32_t* nelesinbin, uint32_t* outbitlen);
void kk_ot_extension_server(uint8_t* hash_table, uint32_t nbins, uint32_t totaleles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt, uint32_t nthreads, uint8_t* res_buf, uint8_t* ret, CBitVector vRcv, CBitVector m_nU);


/**
 * @Zichen
 * Functions used for CLIENT
*/
uint32_t semi_ot_psi_init_client(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t elebitlen,
						uint32_t ntasks, prf_state_ctx* prf_state, uint8_t* hash_table,
						uint32_t* outbitlen, uint32_t* nelesinbin, uint32_t* perm);
void kk_ot_extension_client(uint8_t* hash_table, uint32_t nbins, uint32_t neles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt, uint32_t nthreads, uint8_t* res_buf, uint8_t* ret);
uint32_t semi_ot_psi_result_client(uint32_t** result, uint8_t* masks,
		uint32_t neles, uint8_t* server_masks, uint32_t pneles, uint32_t maskbytelen, uint32_t* perm);
uint32_t bee_otpsi_find_intersection(uint32_t** result, uint8_t* my_hashes,
		uint32_t my_neles, uint8_t* pa_hashes, uint32_t pa_neles, uint32_t hashbytelen, uint32_t* perm);


/**
 * @Zichen
 * General functions.
*/
bool semi_ot_psi_prepare(uint32_t neles, uint32_t pneles, uint8_t** elements, uint32_t* elebytelens, uint32_t* maskbytelen,
                         uint8_t* eleptr, uint32_t* internal_bitlen, uint32_t* maskbitlen, crypto* crypt_env);

#endif //BEE_OT_PSI_ALGORITHM_H_