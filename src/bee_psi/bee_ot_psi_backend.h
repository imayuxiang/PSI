/*
 * bee_ot_psi_backend.h
 *
 *  Created on: Sep 10, 2020
 *      Author: ly
 *  Function: 
 *      A demo shows the function that has to be implemented by the backend.
 */

#ifndef BEE_OT_PSI_BACKEND_H_
#define BEE_OT_PSI_BACKEND_H_

// #include "../pk-based/dh-psi.h"
// #include "../naive-hashing/naive-psi.h"
#include <fstream>
#include <iostream>
#include <string>
// #include "bee_networking.h"
#include "bee_ot_psi_algorithm.h"
#include "../util/parse_options.h"
#include "../util/helpers.h"

/*
*   Protocol Type
*/
#define SEMI_OT_PSI 0
#define SEMI_ECC_DH_PSI 1
#define INSECURE_NAIVE_HASH 2
#define DEFAULT 0

/*
*   Party type
*/
#define SERVER 0
#define CLIENT 1 // client gets the intersection result

using namespace std;

typedef struct{
    double epsilon; // algorithm parameters
    uint32_t ele_byte_len; // element length
    uint32_t security_level; // security level, default = 128
    uint32_t n_thread; // the number of thread for computation
    uint32_t n_clients; // default = 2, do not support > 2
    role_type party; // 
	uint32_t protocol;
}ot_json_para;


void read_para_from_json(ot_json_para* para);

/**
 * @Zichen
 * Delete this function, later
 * */ 
int32_t read_psi_demo_options(int32_t* argcp, char*** argvp, role_type* role, psi_prot* protocol, string* filename, string* address,
		uint32_t* nelements, bool* detailed_timings);


#endif /* BEE_OT_PSI_BACKEND_H_ */