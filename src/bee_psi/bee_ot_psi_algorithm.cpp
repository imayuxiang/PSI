/*
 * bee_ot_psi_algorithm.cpp
 *
 *  Created on: Sep 10, 2020
 *      Author: ly
 *  Function: 
 *      List the functions about algorithm team.
 *      @TODO ZiChen
 */

#include "bee_ot_psi_algorithm.h"


/**
 * @Zichen
 * General functions.
*/
bool semi_ot_psi_prepare(uint32_t neles, uint32_t pneles, uint8_t** elements, uint32_t* elebytelens, uint32_t* maskbytelen,
                         uint8_t* eleptr, uint32_t* internal_bitlen, uint32_t* maskbitlen, crypto* crypt_env){
	// the bit length of masked elements, which is equal to securty level + log2(k * n_1) + log2_(n_2)
	*maskbitlen = pad_to_multiple(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
	// the byte length of masked elements, masked bit length divided by 8
	*maskbytelen = ceil_divide(*maskbitlen, 8);

	//Hash elements into a smaller domain
	eleptr = (uint8_t*) malloc((*maskbytelen) * neles);

	// @ly
	// to unify and shorten the length id info, first hash the elements into a small domain
	// theoretically, the number of the elements in the domain $n$ and the collision probability $p$ obey the following correlation:
	// p = n^2 / (2 * 2^d)
	domain_hashing(neles, elements, elebytelens, eleptr, *maskbytelen, crypt_env);
	
	*internal_bitlen = *maskbitlen;

    return true;
}


/**
 * @Zichen
 * Functions used for SERVER
*/
void semi_ot_psi_init_server(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t pneles, uint32_t elebitlen, uint32_t maskbitlen,
		crypto* crypt_env, uint32_t ntasks, prf_state_ctx* prf_state, uint8_t* hash_table, uint32_t* nelesinbin, uint32_t* outbitlen) {
	uint32_t maskbytelen;
	timeval t_start, t_end;
#ifdef ENABLE_STASH
	uint32_t stashsize = get_stash_size(neles);
#endif
	maskbytelen = ceil_divide(maskbitlen, 8);

	hash_table = simple_hashing(elements, neles, elebitlen, outbitlen, nelesinbin, nbins, ntasks, prf_state);

#ifdef ENABLE_STASH
	//send masks for all items on the stash
	for(uint32_t i = 0; i < stashsize; i++) {
		send_masks(masks, neles, maskbytelen, sock[0]);
	}
#endif
}

void kk_ot_extension_server(uint8_t* hash_table, uint32_t nbins, uint32_t totaleles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt, uint32_t nthreads, uint8_t* res_buf, uint8_t* ret, CBitVector vRcv, CBitVector m_nU){
	CBitVector ht_vec, res_vec;
	beeKkOTCompServer* sender;
	uint32_t maskbytelen = ceil_divide(maskbitlen, 8);

#ifndef BATCH
	cout << "Server: bins = " << nbins << ", elebitlen = " << elebitlen << " and maskbitlen = " <<
			maskbitlen << " and performs " << nbins << " OTs" << endl;
#endif

	sender = new beeKkOTCompServer(m_nCodeWordBits, elebitlen, crypt, m_nU);

	ht_vec.AttachBuf(hash_table, totaleles * ceil_divide(elebitlen, 8));
	res_vec.AttachBuf(res_buf, totaleles * maskbytelen);

    sender->OTBaseProcessRecv(ret);
	// sender->initKkOTSender(nbins, maskbitlen, &ht_vec, &res_vec, nthreads, nelesinbin, vRcv);
	// sender->kkOTPreSendRoutine()
}








/**
 * @Zichen
 * Functions used for CLIENT
*/
uint32_t semi_ot_psi_init_client(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t elebitlen,
						uint32_t ntasks, prf_state_ctx* prf_state, uint8_t* hash_table,
						uint32_t* outbitlen, uint32_t* nelesinbin, uint32_t* perm) {
	// uint32_t stashsize = get_stash_size(neles);
	// nelesinbin = (uint32_t*) calloc(nbins, sizeof(uint32_t));
	hash_table = cuckoo_hashing(elements, neles, nbins, elebitlen, outbitlen,
			nelesinbin, perm, ntasks, prf_state);
}



void kk_ot_extension_client(uint8_t* hash_table, uint32_t nbins, uint32_t neles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt, uint32_t nthreads, uint8_t* res_buf, uint8_t* ret){
	CBitVector ht_vec, res_vec;
	uint32_t maskbytelen = ceil_divide(maskbitlen, 8);;
	beeKkOTCompClient* receiver;
	timeval t_start, t_end;

#ifndef BATCH
	cout << "Client: bins = " << nbins << ", elebitlen = " << elebitlen << " and maskbitlen = " <<
			maskbitlen << " and performs " << nbins << " OTs" << endl;
#endif

	// receiver = new beeKkOTCompClient(m_nCodeWordBits, elebitlen, crypt);

	// ht_vec.AttachBuf(hash_table, nbins * ceil_divide(elebitlen, 8));
	// res_vec.AttachBuf(res_buf, neles * maskbytelen);
	// res_vec.Reset();

	// receiver->NPBaseOTSend(ret);
	// receiver->receive(nbins, maskbitlen, &ht_vec, &res_vec, nthreads, nelesinbin);	
}


uint32_t semi_ot_psi_result_client(uint32_t** result, uint8_t* masks,
		uint32_t neles, uint8_t* server_masks, uint32_t pneles, uint32_t maskbytelen, uint32_t* perm){

#ifdef ENABLE_STASH
	//receive the masks for the stash
	//cout << "allocating a stash of size " << pneles << " * " << maskbytelen << " * " << stashsize << endl;
	uint8_t* stashmasks = (uint8_t*) malloc(pneles * maskbytelen * stashsize);
	rcv_ctx.rcv_buf = server_masks;
	rcv_ctx.nmasks = stashsize * pneles;
	rcv_ctx.maskbytelen = maskbytelen;
	rcv_ctx.sock = sock;
	if(pthread_create(&rcv_masks_thread, NULL, receive_masks, (void*) (&rcv_ctx))) {
		cerr << "Error in creating new pthread at cuckoo hashing!" << endl;
		exit(0);
	}
#endif

	//compute intersection
	uint32_t intersect_size = bee_otpsi_find_intersection(result, masks, neles, server_masks,
			pneles * NUM_HASH_FUNCTIONS, maskbytelen, perm);

#ifdef ENABLE_STASH
	//wait for receiving thread
	if(pthread_join(rcv_masks_thread, NULL)) {
		cerr << "Error in joining pthread at cuckoo hashing!" << endl;
		exit(0);
	}
	free(stashmasks);
#endif

	return intersect_size;
}






//TODO if this works correctly, combine with other find intersection methods and outsource to hashing_util.h
uint32_t bee_otpsi_find_intersection(uint32_t** result, uint8_t* my_hashes,
		uint32_t my_neles, uint8_t* pa_hashes, uint32_t pa_neles, uint32_t hashbytelen, uint32_t* perm) {

	uint32_t keys_stored;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * my_neles);
	uint32_t* tmpval;
	uint64_t tmpbuf;
	uint32_t* tmpkeys;
	uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * my_neles);

	for(uint32_t i = 0; i < my_neles; i++) {
		assert(perm[i] < my_neles);
		invperm[perm[i]] = i;
	}

	uint32_t size_intersect, i, intersect_ctr, tmp_hashbytelen;

	//tmp_hashbytelen; //= min((uint32_t) sizeof(uint64_t), hashbytelen);
	if(sizeof(uint64_t) < hashbytelen) {
		keys_stored = 2;
		tmp_hashbytelen = sizeof(uint64_t);
		tmpkeys = (uint32_t*) calloc(my_neles * keys_stored, sizeof(uint32_t));
		for(i = 0; i < my_neles; i++) {
			memcpy(tmpkeys + 2*i,  my_hashes + i*hashbytelen + tmp_hashbytelen, hashbytelen-sizeof(uint64_t));
			memcpy(tmpkeys + 2*i + 1, perm + i, sizeof(uint32_t));
		}
	} else {
		keys_stored = 1;
		tmp_hashbytelen = hashbytelen;
		tmpkeys = (uint32_t*) malloc(my_neles * sizeof(uint32_t));
		memcpy(tmpkeys, perm, my_neles * sizeof(uint32_t));
	}

	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < my_neles; i++) {
		tmpbuf=0;
		memcpy((uint8_t*) &tmpbuf, my_hashes + i*hashbytelen, tmp_hashbytelen);
		//cout << "Insertion, " << i << " = " <<(hex) << tmpbuf << endl;
		//for(uint32_t j = 0; j < tmp_hashbytelen; j++)

		g_hash_table_insert(map,(void*) &tmpbuf, &(tmpkeys[i*keys_stored]));
	}

	for(i = 0, intersect_ctr = 0; i < pa_neles; i++) {
		//tmpbuf=0;
		memcpy((uint8_t*) &tmpbuf, pa_hashes + i*hashbytelen, tmp_hashbytelen);
		//cout << "Query, " << i << " = " <<(hex) << tmpbuf << (dec) << endl;
		if(g_hash_table_lookup_extended(map, (void*) &tmpbuf, NULL, (void**) &tmpval)) {
			if(keys_stored > 1) {
				tmpbuf = 0;
				memcpy((uint8_t*) &tmpbuf, pa_hashes + i*hashbytelen+sizeof(uint64_t), hashbytelen-sizeof(uint64_t));
				if((uint32_t) tmpbuf == tmpval[0]) {
					matches[intersect_ctr] = tmpval[1];
					if(intersect_ctr<my_neles)
						intersect_ctr++;
				//cout << "Match found at " << tmpval[0] << endl;
				}
			} else {
				//cout << "I have found a match for mask " << (hex) << tmpbuf << (dec) << endl;
				matches[intersect_ctr] = tmpval[0];
				//cout << "intersection found at position " << tmpval[0] << " for key " << (hex) << tmpbuf << (dec) << endl;
				if(intersect_ctr<my_neles)
					intersect_ctr++;
				//cout << "Match found at " << tmpval[0] << " for i = " << i << endl;
			}


		}
	}
	//cout << "Number of matches: " << intersect_ctr << ", my neles: " << my_neles << ", hashbytelen = " << hashbytelen << endl;
	assert(intersect_ctr <= my_neles);
	/*if(intersect_ctr > my_neles) {
		cerr << "more intersections than elements: " << intersect_ctr << " vs " << my_neles << endl;
		intersect_ctr = my_neles;
	}*/
	size_intersect = intersect_ctr;

	(*result) = (uint32_t*) malloc(sizeof(uint32_t) * size_intersect);
	memcpy(*result, matches, sizeof(uint32_t) * size_intersect);

	//cout << "I found " << size_intersect << " intersecting elements" << endl;

	free(matches);
	free(invperm);
	free(tmpkeys);
	return size_intersect;
}
