#ifndef FOPAS_SCHEME_H
#define FOPAS_SCHEME_H

#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "time.h"
#include "test_extras.h"

#include "conf.h"
#include "util.c"
#include "tree_util.c"


/*
 *  Function:       FOPAS_kg: key generation of the FPAS scheme
 *
 * sk               secret key structure
 * pk               public key structure
 * 
*/
ECCRYPTO_STATUS FOPAS_kg(struct secret_key *sk, struct public_key *pk)
{
    ECCRYPTO_STATUS status = ECCRYPTO_SUCCESS;

    // Generate the private/public key
    if (0 == RAND_bytes(sk->y, 32))                                                                 { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) sk->y, (digit_t*) sk->y);
    ecc_mul_fixed((digit_t*) sk->y, pk->Y);

    // Generate the private/public ephemeral keys
    for (int i = 0; i < BPV_K; i++)
    {
        if (0 == RAND_bytes(sk->r[i], 32))                                                          { return ECCRYPTO_ERROR; }
        modulo_order((digit_t*) sk->r[i], (digit_t*) sk->r[i]);
        ecc_mul_fixed((digit_t*) sk->r[i], sk->R[i]);
    }
    // Generate the root of the seed tree
    if (0 == RAND_bytes(sk->x_0, 32))                                                               { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) sk->x_0, (digit_t*) sk->x_0);
    sk->i = sk->j = 1;
    memset(pk->R_A, 0, 64);
    memset(pk->s_A, 0, 32);


    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       FOPAS_Sign: signature generation of FPAS scheme
 *
 * sk               secret key structure
 * msg              message to be signed
 * msglen           length of the message
 * sig              signature to be generated
 * 
*/
ECCRYPTO_STATUS FOPAS_Sign(struct secret_key *sk, size_t depth, size_t SCT_L2,
                           uint8_t *msg, struct signature *sig, DS *X_i)
{
    uint8_t                 x_ij[SEED_SIZE],e_j[32], s_j[32], me_j[32], my[32], pre_hash[MSG_SIZE + 32], r_bpv[32];
    point_t                 R_bpv, R_bpv1;
    int                     r_indices[BPV_V];
    point_extproj_t         R_bpv_proj, R_i_proj;
    point_extproj_precomp_t R_i_proj_pre;


    if (sk->i > (1 << depth))                                                                       { return ECCRYPTO_ERROR; }
    if (sk->j == 1) {
        if (ECCRYPTO_ERROR == seed_traverse(sk->x_0, 0, 1, sk->x_i, depth, sk->i))                  { return ECCRYPTO_ERROR; }
    }
    
    // compute the ephemeral key "e_i^j"
    if (ECCRYPTO_ERROR == sha256_i(sk->x_i, SEED_SIZE, x_ij, sk->j))                                { return ECCRYPTO_ERROR; }
    memmove(pre_hash, msg, MSG_SIZE);
    memmove(pre_hash + MSG_SIZE, x_ij, 32);
    if (NULL == SHA256(pre_hash, MSG_SIZE + 32, e_j))                                               { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) e_j, (digit_t*) e_j);

    // compute the nonce commitment key for the current iteration "j" in epoch "i"
    for (int i = 0 ; i < BPV_V ; i++) {
        r_indices[i] = (16 * e_j[2*i] + e_j[2*i+1]) % BPV_K;
    }

    memcpy(r_bpv, sk->r[r_indices[0]], 32);
    for (int i = 1 ; i < BPV_V ; i++) {
        add_mod_order((digit_t*) r_bpv, (digit_t*) sk->r[r_indices[i]], (digit_t*) r_bpv);
    }
    point_setup(sk->R[r_indices[0]], R_bpv_proj);
    for (int i = 1 ; i < BPV_V ; i++) {
        point_setup(sk->R[r_indices[i]], R_i_proj);
        R1_to_R2(R_i_proj, R_i_proj_pre);
        eccadd(R_i_proj_pre, R_bpv_proj);
    }
    eccnorm(R_bpv_proj, R_bpv);

    // compute the signature "e * y"
    to_Montgomery((digit_t*) e_j, (digit_t*) me_j);
    to_Montgomery((digit_t*) sk->y, (digit_t*) my);
    Montgomery_multiply_mod_order((digit_t*) me_j, (digit_t*) my, (digit_t*) s_j);
    from_Montgomery((digit_t*) s_j, (digit_t*) s_j);
    // compute the signature "s <- r - e * y"
    subtract_mod_order((digit_t*) r_bpv, (digit_t*) s_j, (digit_t*) s_j);

    // fill the signature components
    sig->i = sk->i;
    sig->j = sk->j;
    memmove(sig->s, s_j, 32);
    memmove(sig->R, R_bpv, 64);

    if (sk->j == SCT_L2) {
        if (ECCRYPTO_ERROR == seed_optimizer(sk->x_0, sk->i, X_i, depth))                           { return ECCRYPTO_ERROR; }
        sk->i ++; sk->j = 1;
    } else {
        sk->j++;
    }


    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       FOPAS_Ver: signature verification of FPAS scheme
 *
 * 
*/
ECCRYPTO_STATUS FOPAS_Ver(struct public_key *pk, size_t SCT_L1, size_t SCT_L2, uint8_t *msg,
                          DS X_i, struct signature sig[], int *valid)
{
    uint8_t e_j[32], x_i[SEED_SIZE], x_j[SEED_SIZE], pre_hash[MSG_SIZE + SEED_SIZE];
    point_t R_s[64];
    int     iter, epoch = sig[0].i;
    
    // retrieve the seed that corresponds to the given epoch
    if (ECCRYPTO_ERROR == retrieve_seed(x_i, epoch, X_i, SCT_L1))                                   { return ECCRYPTO_ERROR; }
    
    for (iter = 0 ; iter < SCT_L2 ; iter++) {
        // Derive the seed of the current iteration from the one of current epoch
        if (ECCRYPTO_ERROR == sha256_i(x_i, SEED_SIZE, x_j, sig[iter].j))                           { return ECCRYPTO_ERROR; }
        // compute the e component
        memmove(pre_hash, msg + iter * MSG_SIZE, MSG_SIZE);
        memmove(pre_hash + MSG_SIZE, x_j, SEED_SIZE);
        if (NULL == SHA256(pre_hash, MSG_SIZE + 32, e_j))                                           { return ECCRYPTO_ERROR; }
        modulo_order((digit_t*) e_j, (digit_t*) e_j);

        // compute R' <- s * G + e * Y
        ecc_mul_double((digit_t*) sig[iter].s, (point_affine*) pk->Y, (digit_t*) e_j, (point_affine*) R_s);
        // verify the validity of the signature
        if (0 != (valid[iter] = memcmp(sig[iter].R, R_s, 64))) {
            pk->failed_indices[(sig[iter].i - 1) * SCT_L2 + sig[iter].j] ++;
            pk->failed_sigs[(sig[iter].i - 1) * SCT_L2 + sig[iter].j] = sig[iter];
        }
    }

    pk->X_i = X_i;

    
    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       FOPAS_Distill: signature distillation of FPAS scheme
 *
 * 
*/
ECCRYPTO_STATUS FOPAS_Distill(struct public_key *pk, size_t SCT_L2,
                             struct signature sig[], int *valid)
{
    ECCRYPTO_STATUS         status;
    int                     iter;
    point_extproj_t         R1, RA;
    point_extproj_precomp_t R_tmp;
    point_t                 R_A;


    memset(R_A, 0, sizeof(R_A));
    point_setup(pk->R_A, RA);
    
    for (iter = 0 ; iter < SCT_L2 ; iter++) {
        if (valid[iter] == 0) {
            // add up to the aggregated signature
            add_mod_order((digit_t*) pk->s_A, (digit_t*) sig[iter].s, (digit_t*)  pk->s_A);
            // add up to the public commitment of the aggregated signature
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

#endif
