
#ifndef FOPAS_UTIL_H
#define FOPAS_UTIL_H


#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "time.h"

#include "util.c"
#include "conf.h"
#include "SOCOSLO-util.c"



/*
 *  Function:       FOPAS_sebver: selective batch verification of the valid aggregation signature for FPAS scheme
 *
 * 
*/
ECCRYPTO_STATUS SOPAS_sebver(struct public_key pk,
                               size_t last_epoch, size_t L1, size_t L2,
                               int *valid, char *logpath)
{
    ECCRYPTO_STATUS         status;
    size_t                  iter, epoch, CHUNK_SIZE = L2 * 32;
    uint8_t                 msg[CHUNK_SIZE];
    uint8_t                 e_j[32], e_A[32], e_i[32], x_i[SEED_SIZE], x_j[SEED_SIZE], pre_hash[MSG_SIZE + SEED_SIZE];
    point_t                 R_s, Y;
    std::ifstream           log_file;


    log_file.open(logpath);
    if (!log_file.is_open()) {
        printf("ERROR: Data load failed!\n");
        return ECCRYPTO_ERROR;
    }

    // checking the valid signatures by verifying their corresponding aggregated signature
    memset(e_A, 0, 32);
    for (epoch = 1 ; epoch <= last_epoch ; epoch++) {
        log_file.read((char *) msg, CHUNK_SIZE);
        memset(e_i, 0, 32);
        if (ECCRYPTO_ERROR == retrieve_seed(x_i, epoch, pk.X_i, L1))                                                    { return ECCRYPTO_ERROR; }

        for (iter = 0 ; iter < L2 ; iter++) {
            // Derive the seed of the current iteration from the one of current epoch
            if (ECCRYPTO_ERROR == sha256_i(x_i, SEED_SIZE, x_j, iter+1))                                                { return ECCRYPTO_ERROR; }
            // compute the e component
            memmove(pre_hash, msg + iter * MSG_SIZE, MSG_SIZE);
            memmove(pre_hash + MSG_SIZE, x_j, SEED_SIZE);
            if (NULL == SHA256(pre_hash, MSG_SIZE + SEED_SIZE, e_j))                                                    { return ECCRYPTO_ERROR; }
            modulo_order((digit_t*) e_j, (digit_t*) e_j);
            add_mod_order((digit_t*) e_i, (digit_t*) e_j, (digit_t*) e_i);
        }

        if (pk.failed_indices[epoch] == 0) {
            add_mod_order((digit_t*) e_i, (digit_t*) e_A, (digit_t*) e_A);
        } 
    }

    ecc_mul_double((digit_t*) pk.s_A, pk.Y, (digit_t*) e_A, R_s);
    *valid = memcmp(pk.R_A, R_s, sizeof(R_s));
    if (0 != *valid)                                                                                                    { return ECCRYPTO_ERROR; }


    return ECCRYPTO_SUCCESS;
}

#endif
