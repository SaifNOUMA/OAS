#ifndef FOPAS_SCHEME_H
#define FOPAS_SCHEME_H

#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "time.h"

#include "conf.h"
#include "util.c"
#include "FIPOSLO-util.c"


/*
 *  Function:       FIPOSLO_kg: FIPOSLO's key generation
 *
 * sk               secret key
 * pk               public key
 * 
*/
ECCRYPTO_STATUS FIPOSLO_kg(struct secret_key *sk, struct public_key *pk)
{
    ECCRYPTO_STATUS status = ECCRYPTO_SUCCESS;

    /* generate a private/public key */
    if (0 == RAND_bytes(sk->y, 32))                                                                 { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) sk->y, (digit_t*) sk->y);
    ecc_mul_fixed((digit_t*) sk->y, pk->Y);
    /* generate a private/public ephemeral key pairs */
    for (int i = 0; i < BPV_K; i++)
    {
        if (0 == RAND_bytes(sk->r[i], 32))                                                          { return ECCRYPTO_ERROR; }
        modulo_order((digit_t*) sk->r[i], (digit_t*) sk->r[i]);
        ecc_mul_fixed((digit_t*) sk->r[i], sk->R[i]);
    }
    /* generate the SCT's root */
    if (0 == RAND_bytes(sk->x_0, 32))                                                               { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) sk->x_0, (digit_t*) sk->x_0);
    /* initialize counters */
    sk->i = sk->j = 1;
    memset(pk->R_A, 0, 64);
    memset(pk->s_A, 0, 32);


    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       FIPOSLO_Sign: FIPOSLO's signature generation
 *
 * sk               secret key
 * msg              message to be signed
 * msglen           message length
 * sig              signature to be generated
 * 
*/
ECCRYPTO_STATUS FIPOSLO_Sign(struct secret_key *sk, size_t depth, size_t SCT_L2,
                           uint8_t *msg, struct signature *sig, DS *X_i)
{
    int                     i, r_indices[BPV_V];
    uint8_t                 x_ij[SEED_SIZE], e_j[32], s_j[32], me_j[32], my[32], pre_hash[MSG_SIZE + 32], r_bpv[32];
    point_t                 R_bpv, R_bpv1;
    point_extproj_t         R_bpv_proj, R_i_proj;
    point_extproj_precomp_t R_i_proj_pre;


    /* check the epoch and iteration counters */
    if (sk->i > (1 << depth))                                                                       { return ECCRYPTO_ERROR; }
    if (sk->j == 1) {
        if (ECCRYPTO_ERROR == seed_traverse(sk->x_0, 0, 1, sk->x_i, depth, sk->i))                  { return ECCRYPTO_ERROR; }
    }

    /* compute the ephemeral key "e_i^j" */
    if (ECCRYPTO_ERROR == sha256_i(sk->x_i, SEED_SIZE, x_ij, sk->j))                                { return ECCRYPTO_ERROR; }
    memmove(pre_hash, msg, MSG_SIZE);
    memmove(pre_hash + MSG_SIZE, x_ij, 32);
    if (NULL == SHA256(pre_hash, MSG_SIZE + 32, e_j))                                               { return ECCRYPTO_ERROR; }
    modulo_order((digit_t*) e_j, (digit_t*) e_j);

    /* compute the private commitment "r" for the j^th iteration in the i^th epoch */
    for (i = 0 ; i < BPV_V ; i++) {
        r_indices[i] = (16 * e_j[2*i] + e_j[2*i+1]) % BPV_K;
    }

    memcpy(r_bpv, sk->r[r_indices[0]], 32);
    for (i = 1 ; i < BPV_V ; i++) {
        add_mod_order((digit_t*) r_bpv, (digit_t*) sk->r[r_indices[i]], (digit_t*) r_bpv);
    }
    point_setup(sk->R[r_indices[0]], R_bpv_proj);
    for (i = 1 ; i < BPV_V ; i++) {
        point_setup(sk->R[r_indices[i]], R_i_proj);
        R1_to_R2(R_i_proj, R_i_proj_pre);
        eccadd(R_i_proj_pre, R_bpv_proj);
    }
    eccnorm(R_bpv_proj, R_bpv);

    /* compute the signature "s <- r - e * y"  */
    to_Montgomery((digit_t*) e_j, (digit_t*) me_j);
    to_Montgomery((digit_t*) sk->y, (digit_t*) my);
    Montgomery_multiply_mod_order((digit_t*) me_j, (digit_t*) my, (digit_t*) s_j);
    from_Montgomery((digit_t*) s_j, (digit_t*) s_j);
    subtract_mod_order((digit_t*) r_bpv, (digit_t*) s_j, (digit_t*) s_j);

    /* fill the output variables */
    sig->i = sk->i;
    sig->j = sk->j;
    memmove(sig->s, s_j, 32);
    memmove(sig->R, R_bpv, 64);

    /* disclose the required seeds */
    if (sk->j == SCT_L2) {
        if (ECCRYPTO_ERROR == seed_optimizer(sk->x_0, sk->i, X_i, depth))                           { return ECCRYPTO_ERROR; }
        sk->i ++; sk->j = 1;
    } else {
        sk->j++;
    }


    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       FIPOSLO_Ver: FIPOSLO's signature verification
 *
 * 
*/
ECCRYPTO_STATUS FIPOSLO_Ver(struct public_key *pk, size_t SCT_L1, size_t SCT_L2,
                           uint8_t *msg, DS X_i, struct signature sig[],
                           int *valid)
{
    int     iter;
    point_t R_s[64];
    uint8_t e_j[32], x_i[SEED_SIZE], x_j[SEED_SIZE], pre_hash[MSG_SIZE + SEED_SIZE];
    
    /* retrieve the seed that corresponds to the given epoch */
    if (ECCRYPTO_ERROR == retrieve_seed(x_i, sig[0].i, X_i, SCT_L1))                                { return ECCRYPTO_ERROR; }
    
    for (iter = 0 ; iter < SCT_L2 ; iter++) {
        /* Derive the seed "x_i^j" */
        if (ECCRYPTO_ERROR == sha256_i(x_i, SEED_SIZE, x_j, sig[iter].j))                           { return ECCRYPTO_ERROR; }

        /* compute the component "e" */
        memmove(pre_hash, msg + iter * MSG_SIZE, MSG_SIZE);
        memmove(pre_hash + MSG_SIZE, x_j, SEED_SIZE);
        if (NULL == SHA256(pre_hash, MSG_SIZE + 32, e_j))                                           { return ECCRYPTO_ERROR; }
        modulo_order((digit_t*) e_j, (digit_t*) e_j);

        /* compute "R' <- s * G + e * Y" */
        ecc_mul_double((digit_t*) sig[iter].s, (point_affine*) pk->Y, (digit_t*) e_j, (point_affine*) R_s);
        /* verify the validity of the signature */
        if (0 != (valid[iter] = memcmp(sig[iter].R, R_s, 64))) {
            pk->failed_indices[(sig[iter].i - 1) * SCT_L2 + sig[iter].j] ++;
            pk->failed_sigs[(sig[iter].i - 1) * SCT_L2 + sig[iter].j] = sig[iter];
        }
    }

    pk->X_i = X_i;

    
    return ECCRYPTO_SUCCESS;
}

#endif
