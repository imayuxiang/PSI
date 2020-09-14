/*
 * bee_ot_psi_backend.cpp
 *
 *  Created on: Sep 10, 2020
 *      Author: ly
 *  Function: 
 *      A demo shows the function that has to be implemented by the backend.
 */

#include "bee_ot_psi_backend.h"


/**
 * Some parameters used for this demo
 * 
*/
#define SERVER_FILE_NAME "sample_sets/emails_alice.txt"
#define CLIENT_FILE_NAME "sample_sets/emails_bob.txt"


void read_para_from_json(ot_json_para* para){
    // @ZiChen Todo, read parameters from json
    para->epsilon = 1.2;
    para->ele_byte_len = 32;
    para->n_thread = 10;
    para->protocol = SEMI_OT_PSI;
    para->security_level = 128;
    para->party = (role_type) SERVER;
    para->n_clients = 2;
}

static void exchange_random_seed(uint8_t* seed_buf, uint8_t* seed_recv_buf){
    // see bee_networking.h
}

void bee_read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename);




bool semi_ot_psi_backend(){
    /**
     * @Zichen
     * The following parameters are loaded from json, which are about algorithms
     * 
    */
    double epsilon;
	uint32_t elebytelen;
    uint32_t security_level;
    uint32_t ntasks;
    uint32_t nclients;
	role_type role;
	uint32_t protocol;


    /**
     * @Zichen
     * The following parameters are declared by the backend
     * Most of them are about data storage, the values of which are set while running
    */
    uint32_t nelements=0, *elebytelens;
    uint32_t i, j;
    uint32_t pnelements;
    uint32_t intersect_size = 0, *res_bytelens;
    uint8_t **elements, **intersection;

    /**
     * @Zichen
     * The following parameters are set by the backend
     * Most of them are about networking
    */
    string address="127.0.0.1";
    uint16_t port=7766;
    vector<CSocket> sockfd(ntasks);
    string filename;
    
    /**
     * @Zichen
     * The following parameters are used for performance evaluation
     * 
    */
	uint64_t bytes_sent=0, bytes_received=0, mbfac;
	bool detailed_timings=true;
	timeval t_start, t_end;
	
	
    /**
     *  Read parameters from json 
     **/
    ot_json_para* server_para = (ot_json_para* )malloc(sizeof(ot_json_para));
    read_para_from_json(server_para);
    epsilon = server_para->epsilon;
    elebytelen = server_para->ele_byte_len;
    security_level = server_para->security_level;
    ntasks = server_para->n_thread;
    nclients = server_para->n_clients;
	role = server_para->party;
	protocol = server_para->protocol;


    /**
     * @ZiChen TODO
     * Set all necessary parameters required for out algorithms
     * can be ignored and implemented on the above
    */
    mbfac=1024*1024;
    

	/*
		@ly
		protocol: three kinds of PSI protocols
		filename: input file
		address: ip address
		port: port number (add)
		nelements: the number of elements required to be intersected
	*/
	
	// if(role == SERVER) {
	// 	if(protocol == TTP) {
	// 		sockfd.resize(nclients);
	// 		listen(address.c_str(), port, sockfd.data(), nclients);
	// 	}
	// 	else
	// 		listen(address.c_str(), port, sockfd.data(), ntasks);
	// } else {
	// 	for(i = 0; i < ntasks; i++)
	// 		connect(address.c_str(), port, sockfd[i]);
	// }

	gettimeofday(&t_start, NULL);

	//read in files and get elements and byte-length from there
	/*	
		@ly
		elements: store the elements
		elebytelens: the bit length of each element, affect the effciency of our algorithm
		nelements: the number of 
	*/
	bee_read_elements(&elements, &elebytelens, &nelements, filename);

	if(detailed_timings) {
		gettimeofday(&t_end, NULL);
	}


	pnelements = exchange_information(nelements, elebytelen, security_level, ntasks, protocol, sockfd[0]);
	//cout << "Performing private set-intersection between " << nelements << " and " << pnelements << " element sets" << endl;

	if(detailed_timings) {
		cout << "Time for reading elements:\t" << fixed << std::setprecision(2) << getMillies(t_start, t_end)/1000 << " s" << endl;
	}


    /**
     * @Zichen
     * This instance has to be returned to Java and invoked for many times.
    */
	crypto crypto_env = get_crypto_instance(security_level);
    prf_state_ctx prf_state;
    uint8_t* seed_buf;
    uint8_t* seed_recv_buf;
    exchange_random_seed(seed_buf, seed_recv_buf);
    crypto_env.gen_common_seed(&prf_state, seed_buf, seed_recv_buf);

    // An important parameter for the hash related psi algorithm
    uint32_t nbins = ceil(epsilon * pnelements);
	
    if(role == SERVER){
        uint32_t maskbytelen, internal_bitlen;
        uint32_t maskbitlen;
        uint8_t* eleptr;
        semi_ot_psi_prepare(nelements, pnelements, elements, elebytelens, &maskbytelen, eleptr,
                                &internal_bitlen, &maskbitlen, &crypto_env);

        uint8_t* hash_table;
        uint32_t* nelesinbin = (uint32_t*) malloc(sizeof(uint32_t) * nbins);
        uint32_t* outbitlen = (uint32_t*) malloc(sizeof(uint32_t));
        semi_ot_psi_init_server(eleptr, nelements, nbins, pnelements,
             internal_bitlen, maskbitlen, &crypto_env, ntasks, &prf_state, hash_table, nelesinbin, outbitlen);

        /**
         * Conduct base OT
        */
        NaorPinkas* bot = new NaorPinkas(&crypto_env, ECC_FIELD);

        /**
         * @Zichen
         * Base OT prepares
        */
        uint32_t nSndVals = 2, nOTs = m_nCodeWordBits;
        uint32_t* fe_bytes = (uint32_t*)malloc(sizeof(uint32_t));
        num** pK = (num**) malloc(sizeof(num*) * nOTs);
        fe** PK_sigma = (fe**) malloc(sizeof(fe*) * nOTs);
        bot->processReceiverPre(nSndVals, nOTs, fe_bytes, PK_sigma, pK);

        /**
         * @ZiChen
         * Receive pBuf
        */
        uint32_t nBufSize = nSndVals * (*fe_bytes);
        // socket->Receive(pBuf, nBufSize);

        /**
         * @ZiChen
         * Process Received data
        */
        brickexp *bc;
        uint8_t* pBuf = (uint8_t*) malloc(sizeof(uint8_t) * nOTs * (*fe_bytes));
        CBitVector choices;
	    choices.Create(nOTs);
	    crypto_env.gen_rnd(choices.GetArr(), ceil_divide(nOTs, 8));
        bot->processReceiverReceive(nSndVals, *fe_bytes, nOTs, pBuf, bc, PK_sigma, choices);

        /**
         * @Zichen
         * send function
        */

        // socket->Send(pBuf, nOTs * crypto_env->fe_byte_size());
        
        /**
         * @ZiChen
         * Process Received data
        */
        uint8_t* ret = (uint8_t*) malloc(m_nCodeWordBits * crypto_env.get_hash_bytes());;
        bot->processReceiverSend(nOTs, ret, bc, fe_bytes, pK);


        /**
         * Conduct  KK-OT-Extension
        */
        uint8_t *masks = (uint8_t*) malloc(NUM_HASH_FUNCTIONS * nelements * maskbytelen);
        uint64_t numOTs = pad_to_multiple(nbins, REGISTER_BITS);
        uint64_t processed_ot_blocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(numOTs, (uint64_t) m_nCodeWordBits));
        uint64_t processed_ots = processed_ot_blocks * m_nCodeWordBits;
        CBitVector vRcv(m_nCodeWordBits * processed_ots);
        CBitVector ht_vec, res_vec;
        uint32_t totaleles = nelements * NUM_HASH_FUNCTIONS;
        beeKkOTCompServer* sender = new beeKkOTCompServer(m_nCodeWordBits, *outbitlen, &crypto_env, choices);

        #ifndef BATCH
            cout << "Server: bins = " << nbins << ", elebitlen = " << *outbitlen << " and maskbitlen = " <<
                    maskbitlen << " and performs " << nbins << " OTs" << endl;
        #endif

        ht_vec.AttachBuf(hash_table, totaleles * ceil_divide(*outbitlen, 8));
	    res_vec.AttachBuf(masks, totaleles * maskbytelen);
        sender->OTBaseProcessRecv(ret);
        sender->initKkOTSender(nbins, maskbitlen, &ht_vec, &res_vec, nelesinbin, vRcv);

        /**
         * @Zichen
         * This place can be processed throught multiple threads.
         * Can be refered in bee_kk_ot_extension.cpp (function processSenderData)
         * Here, directly receive all data processed in one thread.
        */

        // sock->Receive(vRcv.GetArr(), processed_ots * m_nCodeWordBytes);
        sender->kkOTPreSendRoutine(numOTs, vRcv);
        
        /* kk_ot_extension_server(hash_table, nbins, nelements * NUM_HASH_FUNCTIONS, nelesinbin, *outbitlen, 
                                    maskbitlen, &crypto_env, ntasks, masks, ret, vRcv, choices);*/

        /**
         * @Zichen
         * send function
        */
        // sock.Send(masks, nelements * NUM_HASH_FUNCTIONS * maskbytelen);

        free(masks);
        free(hash_table);
        free(nelesinbin);
        free(eleptr);
        free(outbitlen);
        free(ret);
        free(pBuf);
        free(fe_bytes);
        free(PK_sigma);
	    free(pK);
    }
    else if(role == CLIENT){
        uint32_t maskbytelen, internal_bitlen;
        uint32_t maskbitlen;
        uint8_t* eleptr;
        semi_ot_psi_prepare(nelements, pnelements, elements, elebytelens, &maskbytelen, eleptr,
                                &internal_bitlen, &maskbitlen, &crypto_env);

        /**
         * @Zichen
         * ot based PSI preparation
        */
        uint32_t* outbitlen = (uint32_t*) malloc(sizeof(uint32_t));
        uint32_t* nelesinbin = (uint32_t*) calloc(nbins, sizeof(uint32_t));
	    uint8_t* hash_table;
        uint32_t* perm = (uint32_t*) calloc(nelements, sizeof(uint32_t));
        semi_ot_psi_init_client(eleptr, nelements, nbins, internal_bitlen, ntasks, &prf_state, hash_table, outbitlen, nelesinbin, perm);


        /**
         * Conduct base OT
        */
        NaorPinkas* bot = new NaorPinkas(&crypto_env, ECC_FIELD);

        /**
         * @Zichen
         * Base OT prepares
        */
        uint32_t nSndVals = 2, nOTs = m_nCodeWordBits;
        uint32_t nBufSize, fe_bytes;
        num *alpha;
        uint8_t* pBuf;
        fe **pC;
        bot->processSenderPre(nSndVals, &nBufSize, &fe_bytes, alpha, pBuf, pC);

        /**
         * @Zichen
         * Send function
        */
        //socket->Send(pBuf, nBufSize);

        /**
         * @Zichen
         * Process Sent Data
        */
        fe **pCr;
        bot->processSenderSend(nSndVals, nOTs, alpha, pCr, pC);

        /**
         * @Zichen
         * receive function
        */
        free(pBuf);
        // N-P sender: receive pk0
        nBufSize = fe_bytes * nOTs;
        pBuf = (uint8_t*) malloc(nBufSize);
        // socket->Receive(pBuf, nBufSize);


        /**
         * @Zichen
         * Process receive data
        */
        uint8_t* ret = (uint8_t*) malloc(crypto_env.get_hash_bytes() * m_nCodeWordBits * 2);
        bot->processSenderReceive(nSndVals, nOTs, pBuf, fe_bytes, alpha, ret, pCr);


        /**
         * Conduct  KK-OT-Extension
        */
        uint8_t *masks = (uint8_t*) malloc(nelements * maskbytelen);
        CBitVector ht_vec, res_vec;
        uint64_t numOTs = pad_to_multiple(nbins, (uint64_t) REGISTER_BITS);
        beeKkOTCompClient* receiver = new beeKkOTCompClient(m_nCodeWordBits, *outbitlen, &crypto_env);

    #ifndef BATCH
        cout << "Client: bins = " << nbins << ", elebitlen = " << *outbitlen << " and maskbitlen = " <<
                maskbitlen << " and performs " << nbins << " OTs" << endl;
    #endif

        ht_vec.AttachBuf(hash_table, nbins * ceil_divide(*outbitlen, 8));
        res_vec.AttachBuf(masks, nelements * maskbytelen);
        res_vec.Reset();

        receiver->NPBaseOTSend(ret);
        receiver->initKkOTReceiver(nbins, maskbitlen, &ht_vec, &res_vec, nelesinbin);

        uint64_t posIndex = 0, lastPosIndex = 0;
        
        while(posIndex < numOTs){
            lastPosIndex = posIndex;

            //How many batches of OTEXT_BLOCK_SIZE_BITS OTs should be performed?
	        uint64_t processed_ot_blocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(numOTs - posIndex, (uint64_t) m_nCodeWordBits));

            //How many OTs should be performed per iteration
            uint64_t processed_ots = processed_ot_blocks * m_nCodeWordBits;

            // The send buffer
	        CBitVector* vSnd = new CBitVector(m_nCodeWordBits * processed_ots);
            posIndex = receiver->kkOTPreRecvRoutine(posIndex, numOTs, processed_ot_blocks, processed_ots, vSnd);
            
            /**
             * @Zichen
             * Process Sent Data
            */
            // sock->Send(vSnd->GetArr(), m_nCodeWordBytes * (posIndex - lastPosIndex)));

            vSnd->Reset();
	        vSnd->delCBitVector();
        }
        


        uint8_t* server_masks = (uint8_t*) malloc(NUM_HASH_FUNCTIONS * pnelements * maskbytelen);
        /**
         * @Zichen
         * Process receive Data
        */
        // sock.Receive(masks, pnelements * NUM_HASH_FUNCTIONS * maskbytelen);
        uint32_t* res_pos;
        uint32_t intersect_size = 0;
        intersect_size = semi_ot_psi_result_client(&res_pos, masks, nelements, server_masks, pnelements, maskbytelen, perm);

        // uint8_t** intersection; a variable declared above to store intersection results
        // uint8_t* res_bytelen; a variable declared above to store idntity length
        create_result_from_matches_var_bitlen(&intersection, &res_bytelens, elebytelens, elements, res_pos, intersect_size);

        free(eleptr);
        free(outbitlen);
        free(nelesinbin);
        free(hash_table);
        free(perm);
        free(bot);
        free(alpha);
        free(pBuf);
        free(pC);
        free(pCr);
        free(ret);
        free(receiver);
        free(masks);
        free(server_masks);
        free(res_pos);
    }


	gettimeofday(&t_end, NULL);


	if(role == CLIENT) {
		cout << "Computation finished. Found " << intersect_size << " intersecting elements:" << endl;
		if(!detailed_timings) {
			for(i = 0; i < intersect_size; i++) {
				//cout << i << ": \t";
				for(j = 0; j < res_bytelens[i]; j++) {
					cout << intersection[i][j];
				}
				cout << endl;
			}
		}

		for(i = 0; i < intersect_size; i++) {
			free(intersection[i]);
		}
		if(intersect_size > 0)
			free(res_bytelens);
	}

	for(i = 0; i < sockfd.size(); i++) {
		bytes_sent += sockfd[i].get_bytes_sent();
		bytes_received += sockfd[i].get_bytes_received();
	}

	if(detailed_timings) {
		cout << "Required time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end)/1000 << " s" << endl;
		cout << "Data sent:\t" <<	((double)bytes_sent)/mbfac << " MB" << endl;
		cout << "Data received:\t" << ((double)bytes_received)/mbfac << " MB" << endl;
	}


	for(i = 0; i < nelements; i++)
		free(elements[i]);
	free(elements);
	free(elebytelens);
	return 1;
}



/**
 * @Zichen
 * Delete this function, later
 * */ 
int32_t bee_read_psi_demo_options(int32_t* argcp, char*** argvp, role_type* role, psi_prot* protocol, string* filename,
		string* address, uint32_t* nelements, bool* detailed_timings) {

	uint32_t int_role, int_protocol = 0;
	parsing_ctx options[] = {{(void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false},
			{(void*) &int_protocol, T_NUM, 'p', "PSI protocol (0: Naive, 1: TTP, 2: DH, 3: OT)", true, false},
			{(void*) filename, T_STR, 'f', "Input file", true, false},
			{(void*) address, T_STR, 'a', "Server IP-address (needed by both, client and server)", false, false},
			{(void*) nelements, T_NUM, 'n', "Number of elements", false, false},
			{(void*) detailed_timings, T_FLAG, 't', "Flag: Enable detailed timings", false, false}
	};

	if(!parse_options(argcp, argvp, options, sizeof(options)/sizeof(parsing_ctx))) {
		print_usage(argvp[0][0], options, sizeof(options)/sizeof(parsing_ctx));
		exit(0);
	}

	assert(int_role < 2);
	*role = (role_type) int_role;

	assert(int_protocol < PROT_LAST);
	*protocol = (psi_prot) int_protocol;

	return 1;
}

void bee_read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename) {
	uint32_t i, j;
	ifstream infile(filename.c_str());
	if(!infile.good()) {
		cerr << "Input file " << filename << " does not exist, program exiting!" << endl;
		exit(0);
	}
	string line;
	if(*nelements == 0) {
		while (std::getline(infile, line)) {
			++*nelements;
		}
	}
	*elements=(uint8_t**) malloc(sizeof(uint8_t*)*(*nelements));
	*elebytelens = (uint32_t*) malloc(sizeof(uint32_t) * (*nelements));

	infile.clear();
	infile.seekg(ios::beg);
	for(i = 0; i < *nelements; i++) {
		assert(std::getline(infile, line));
		(*elebytelens)[i] = line.length();
		(*elements)[i] = (uint8_t*) malloc((*elebytelens)[i]);
		memcpy((*elements)[i], (uint8_t*) line.c_str(), (*elebytelens)[i]);

#ifdef PRINT_INPUT_ELEMENTS
		cout << "Element " << i << ": ";
		for(j = 0; j < (*elebytelens)[i]; j++)
			cout << (*elements)[i][j];
		cout << endl;
#endif
	}
}

