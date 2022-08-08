
#ifndef FOPAS_UTIL_H
#define FOPAS_UTIL_H


#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "test_extras.h"
#include "time.h"

#include "conf.h"
#include "util.c"
#include "tree_util.c"



/*
 *  Function:       FIPOSA_Distill: FIPOSA's signature distillation
 *
 * 
*/
ECCRYPTO_STATUS FIPOSA_Distill(struct public_key *pk, size_t SCT_L2,
                               struct signature sig[], int *valid)
{
    ECCRYPTO_STATUS         status;
    int                     iter;
    point_t                 R_A;
    point_extproj_t         R1, RA;
    point_extproj_precomp_t R_tmp;


    memset(R_A, 0, sizeof(R_A));
    point_setup(pk->R_A, RA);
    
    for (iter = 0 ; iter < SCT_L2 ; iter++) {
        if (valid[iter] == 0) {
            /* add up to the aggregated signature */
            add_mod_order((digit_t*) pk->s_A, (digit_t*) sig[iter].s, (digit_t*)  pk->s_A);
            /* add up to the public commitment of the aggregated signature */
            if (0 == memcmp(pk->R_A, R_A, sizeof(R_A))) {
                memmove(pk->R_A, sig[iter].R, 64);
                point_setup(pk->R_A, RA);
            } else {
                point_setup(sig[iter].R, R1);
                R1_to_R2(R1, R_tmp);
                eccadd(R_tmp, RA);
            }
        }
    }
    
    eccnorm(RA, R_A);
    memcpy(pk->R_A, R_A, sizeof(R_A));
    

    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       FIPOSA_AuditVer: audit verification of the valid aggregation signature for FPAS scheme
 *
 * 
*/
ECCRYPTO_STATUS FIPOSA_AuditVer(struct public_key pk,
                               size_t last_epoch, size_t L1, size_t L2,
                               int *valid, char *logpath)
{
    ECCRYPTO_STATUS         status;
    size_t                  iter, epoch, CHUNK_SIZE = L2 * 32;
    uint8_t                 msg[CHUNK_SIZE], e_j[L2][32], e_A[32], x_i[SEED_SIZE], x_j[SEED_SIZE], pre_hash[MSG_SIZE + SEED_SIZE];
    point_t                 R_s, R_i, Y;
    std::ifstream           log_file;


    log_file.open(logpath);
    if (!log_file.is_open())                                                                                            { return ECCRYPTO_ERROR; }

    /* checking the valid signatures by verifying their corresponding aggregated signature */
    memset(e_A, 0, 32);
    for (epoch = 1 ; epoch <= last_epoch ; epoch++) {
        log_file.read((char *) msg, CHUNK_SIZE);

        if (ECCRYPTO_ERROR == retrieve_seed(x_i, epoch, pk.X_i, L1))                                                    { return ECCRYPTO_ERROR; }

        for (iter = 0 ; iter < L2 ; iter++) {
            /* Derive the seed of the current iteration from the one of current epoch */
            if (ECCRYPTO_ERROR == sha256_i(x_i, SEED_SIZE, x_j, iter+1))                                                { return ECCRYPTO_ERROR; }
            /* compute the e component */
            memmove(pre_hash, msg + iter * MSG_SIZE, MSG_SIZE);
            memmove(pre_hash + MSG_SIZE, x_j, SEED_SIZE);
            if (NULL == SHA256(pre_hash, MSG_SIZE + SEED_SIZE, e_j[iter]))                                              { return ECCRYPTO_ERROR; }
            modulo_order((digit_t*) e_j[iter], (digit_t*) e_j[iter]);

            if (pk.failed_indices[(epoch-1) * L2 + iter + 1] == 0) {
                add_mod_order((digit_t*) e_j[iter], (digit_t*) e_A, (digit_t*) e_A);
            }
            else {
                /* verify the failed signature individually */
                signature sig = pk.failed_sigs[iter];
                /* compute R' <- s * G + e * Y */
                ecc_mul_double((digit_t*) sig.s, (point_affine*) pk.Y, (digit_t*) e_j, (point_affine*) R_i);

                if (0 == memcmp(sig.R, R_i, sizeof(R_i)))                                                               { return ECCRYPTO_ERROR; }
            }
        }
    }

    ecc_mul_double((digit_t*) pk.s_A, pk.Y, (digit_t*) e_A, R_s);
    *valid = memcmp(pk.R_A, R_s, sizeof(R_s));
    if (0 != *valid)                                                                                                    { return ECCRYPTO_ERROR; }


    return ECCRYPTO_SUCCESS;
}

#endif
