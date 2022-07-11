#ifndef SOPAS_SCHEME_H
#define SOPAS_SCHEME_H

#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "time.h"
#include "test_extras.h"

#include "conf.h"
#include "util.c"
#include "tree_util.c"


/*
 *  Function:       SOPAS_kg: key generation of the FPAS scheme
 *
 * sk               secret key structure
 * pk               public key structure
 * 
*/
ECCRYPTO_STATUS SOPAS_kg(struct secret_key *sk, struct public_key *pk,
                         size_t SCT_L1, size_t SCT_L2)
{
    ECCRYPTO_STATUS status = ECCRYPTO_SUCCESS;
    size_t iter, epoch, t;
    uint8_t r_j[32], r_A[32], prior_hash[SEED_SIZE + sizeof(size_t)];

    // Generate the private/public key
    if (0 == RAND_bytes(sk->y, 32))                                                                 { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) sk->y, (digit_t*) sk->y);
    ecc_mul_fixed((digit_t*) sk->y, pk->Y);

    // Generate the root of the seed tree
    if (0 == RAND_bytes(sk->x_0, 32))                                                               { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) sk->x_0, (digit_t*) sk->x_0);
    sk->i = sk->j = 1;
    memset(pk->R_A, 0, 64);
    memset(pk->s_A, 0, 32);

    // Generate the root of the seed tree
    if (0 == RAND_bytes(sk->r_0, 32))                                                               { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) sk->r_0, (digit_t*) sk->r_0);
    memcpy(prior_hash, sk->r_0, 32);

    for (epoch = 1 ; epoch <= (1 << SCT_L1) ; epoch++) {
        memset(r_A, 0, SEED_SIZE);
        for (iter = 0 ; iter < SCT_L2 ; iter++) {
            t = (epoch - 1) * SCT_L2 + iter + 1;
            memcpy(prior_hash + 32, &t, sizeof(t));
            if (NULL == SHA256(prior_hash, SEED_SIZE + sizeof(size_t), r_j))                        { return ECCRYPTO_ERROR; }
            modulo_order((digit_t*) r_j, (digit_t*) r_j);
            add_mod_order((digit_t*) r_A, (digit_t*) r_j, (digit_t*) r_A);
        }
        if (epoch / 8192 == 0) {
            ecc_mul_fixed((digit_t*) r_A, pk->R[epoch % 8192]);
        } else if (epoch / 8192 == 1) {
            ecc_mul_fixed((digit_t*) r_A, pk->R1[epoch % 8192]);
        } else if (epoch / 8192 == 2) {
            ecc_mul_fixed((digit_t*) r_A, pk->R2[epoch % 8192]);
        } else if (epoch / 8192 == 3) {
            ecc_mul_fixed((digit_t*) r_A, pk->R3[epoch % 8192]);
        } else if (epoch / 8192 == 4) {
            ecc_mul_fixed((digit_t*) r_A, pk->R4[epoch % 8192]);
        }
    }

    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       SOPAS_Sign: signature generation of FPAS scheme
 *
 * sk               secret key structure
 * msg              message to be signed
 * msglen           length of the message
 * sig              signature to be generated
 * 
*/
ECCRYPTO_STATUS SOPAS_Sign(struct secret_key *sk, size_t depth, size_t SCT_L2,
                           uint8_t *msg, struct signature *sig, DS *X_i)
{
    uint8_t                 x_ij[SEED_SIZE],e_j[32], s_j[32], me_j[32], my[32], pre_hash[MSG_SIZE + 32], r_j[32];
    size_t                  t;

    if (sk->i > (1 << depth))                                                                       { return ECCRYPTO_ERROR; }
    if (sk->j == 1) {
        if (ECCRYPTO_ERROR == seed_traverse(sk->x_0, 0, 1, sk->x_i, depth, sk->i))                  { return ECCRYPTO_ERROR; }
        memset(sk->s_A, 0, SEED_SIZE);
    }
    
    // compute the ephemeral key "e_i^j"
    if (ECCRYPTO_ERROR == sha256_i(sk->x_i, SEED_SIZE, x_ij, sk->j))                                { return ECCRYPTO_ERROR; }
    memmove(pre_hash, msg, MSG_SIZE);
    memmove(pre_hash + MSG_SIZE, x_ij, 32);
    if (NULL == SHA256(pre_hash, MSG_SIZE + 32, e_j))                                               { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) e_j, (digit_t*) e_j);

    // compute the nonce commitment key "r_i^j" for the current iteration "j" in epoch "i"
    t = (sk->i - 1) * SCT_L2 + sk->j;
    memcpy(pre_hash, sk->r_0, SEED_SIZE);
    memcpy(pre_hash + SEED_SIZE, &t, sizeof(t));
    if (NULL == SHA256(pre_hash, SEED_SIZE + sizeof(size_t), r_j))                                  { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) r_j, (digit_t*) r_j);
    
    // compute the signature "e * y"
    to_Montgomery((digit_t*) e_j, (digit_t*) me_j);
    to_Montgomery((digit_t*) sk->y, (digit_t*) my);
    Montgomery_multiply_mod_order((digit_t*) me_j, (digit_t*) my, (digit_t*) s_j);
    from_Montgomery((digit_t*) s_j, (digit_t*) s_j);
    // compute the signature "s <- r - e * y"
    subtract_mod_order((digit_t*) r_j, (digit_t*) s_j, (digit_t*) s_j);
    
    // compute the aggregated signature "s_A <- s_A + s_i^j"
    add_mod_order((digit_t*) s_j, (digit_t*) sk->s_A, (digit_t*) sk->s_A);

    if (sk->j == SCT_L2) {
        if (ECCRYPTO_ERROR == seed_optimizer(sk->x_0, sk->i, X_i, depth))                           { return ECCRYPTO_ERROR; }
        // fill the signature components
        sig->i = sk->i;
        memmove(sig->s, sk->s_A, 32);
        sk->i ++; sk->j = 1;
    } else {
        sk->j++;
    }


    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       SOPAS_Ver: signature verification of FPAS scheme
 *
 * 
*/
ECCRYPTO_STATUS SOPAS_Ver(struct public_key *pk, size_t SCT_L1, size_t SCT_L2, uint8_t *msg,
                          DS X_i, struct signature sig, int *valid)
{
    uint8_t x_i[SEED_SIZE], x_j[32], e_j[32], pre_hash[MSG_SIZE + SEED_SIZE], e_A[SEED_SIZE];
    point_t R_s[64];
    int     iter, epoch = sig.i;
    

    memset(e_A, 0, SEED_SIZE);
    // retrieve the seed that corresponds to the given epoch
    if (ECCRYPTO_ERROR == retrieve_seed(x_i, epoch, X_i, SCT_L1))                                   { return ECCRYPTO_ERROR; }
    
    for (iter = 0 ; iter < SCT_L2 ; iter++) {
        // Derive the seed of the current iteration from the one of current epoch
        if (ECCRYPTO_ERROR == sha256_i(x_i, SEED_SIZE, x_j, iter + 1))                              { return ECCRYPTO_ERROR; }
        // compute the e component
        memmove(pre_hash, msg + iter * MSG_SIZE, MSG_SIZE);
        memmove(pre_hash + MSG_SIZE, x_j, SEED_SIZE);
        if (NULL == SHA256(pre_hash, MSG_SIZE + 32, e_j))                                           { return ECCRYPTO_ERROR; }
        modulo_order((digit_t*) e_j, (digit_t*) e_j);
        add_mod_order((digit_t*) e_A, (digit_t*) e_j, (digit_t*) e_A);
    }

    // compute R' <- s * G + e * Y
    ecc_mul_double((digit_t*) sig.s, (point_affine*) pk->Y, (digit_t*) e_A, (point_affine*) R_s);
    // verify the validity of the signature
    if (sig.i / 8192 == 0) {
        if (0 != (*valid = memcmp(pk->R[sig.i % 8192], R_s, 64))) {
            pk->failed_sigs[sig.i] = sig;
            pk->failed_indices[sig.i] ++;
        }
    } else if (sig.i / 8192 == 1) {
            if (0 != (*valid = memcmp(pk->R1[sig.i % 8192], R_s, 64))) {
            pk->failed_sigs[sig.i] = sig;
            pk->failed_indices[sig.i] ++;
        }
    } else if (sig.i / 8192 == 2) {
            if (0 != (*valid = memcmp(pk->R2[sig.i % 8192], R_s, 64))) {
            pk->failed_sigs[sig.i] = sig;
            pk->failed_indices[sig.i] ++;
        }
    } else if (sig.i / 8192 == 3) {
            if (0 != (*valid = memcmp(pk->R3[sig.i % 8192], R_s, 64))) {
            pk->failed_sigs[sig.i] = sig;
            pk->failed_indices[sig.i] ++;
        }
    } else if (sig.i / 8192 == 4) {
            if (0 != (*valid = memcmp(pk->R4[sig.i % 8192], R_s, 64))) {
            pk->failed_sigs[sig.i] = sig;
            pk->failed_indices[sig.i] ++;
        }
    }

    pk->X_i = X_i;

    
    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       SOPAS_Distill: signature distillation of FPAS scheme
 *
 * 
*/
ECCRYPTO_STATUS SOPAS_Distill(struct public_key *pk, size_t SCT_L2,
                             struct signature sig, int valid)
{
    ECCRYPTO_STATUS         status;
    int                     iter;
    point_extproj_t         R1, RA;
    point_extproj_precomp_t R_tmp;
    point_t                 R_A;

    memset(R_A, 0, sizeof(R_A));

    if (valid) {
        return ECCRYPTO_SUCCESS;
    }

    // add up to the aggregated signature
    add_mod_order((digit_t*) pk->s_A, (digit_t*) sig.s, (digit_t*) pk->s_A);
    // add up to the public commitment of the aggregated signature
    if (0 == memcmp(pk->R_A, R_A, sizeof(R_A))) {
        if (sig.i / 8192 == 0) {
            memmove(pk->R_A, pk->R[sig.i % 8192], 64);
        } else if (sig.i / 8192 == 1) {
            memmove(pk->R_A, pk->R1[sig.i % 8192], 64);
        } else if (sig.i / 8192 == 2) {
            memmove(pk->R_A, pk->R2[sig.i % 8192], 64);
        } else if (sig.i / 8192 == 3) {
            memmove(pk->R_A, pk->R3[sig.i % 8192], 64);
        } else if (sig.i / 8192 == 4) {
            memmove(pk->R_A, pk->R4[sig.i % 8192], 64);
        }
    } else {
        point_setup(pk->R_A, RA);
        if (sig.i / 8192 == 0) {
            point_setup(pk->R[sig.i % 8192], R1);
        } else if (sig.i / 8192 == 1) {
            point_setup(pk->R1[sig.i % 8192], R1);
        } else if (sig.i / 8192 == 2) {
            point_setup(pk->R2[sig.i % 8192], R1);
        } else if (sig.i / 8192 == 3) {
            point_setup(pk->R3[sig.i % 8192], R1);
        } else if (sig.i / 8192 == 4) {
            point_setup(pk->R4[sig.i % 8192], R1);
        }
        
        R1_to_R2(R1, R_tmp);
        eccadd(R_tmp, RA);

        eccnorm(RA, R_A);
        memcpy(pk->R_A, R_A, sizeof(R_A));
    }
    

    return ECCRYPTO_SUCCESS;
}

#endif
