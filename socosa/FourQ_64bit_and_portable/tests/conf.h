

#ifndef CONF_H
#define CONF_H


#include <iostream>
#include <stdio.h>
#include <map>
#include <vector>
#include <bitset>



#define BENCH_LOOPS 10000
#define BPV_V       16
#define BPV_K       1024
// #define SCT_L1      20
// #define SCT_L2      256
// #define SCT_T          // 2^27 signatures that can be generated
#define MSG_SIZE    32
#define SEED_SIZE   32
// #define CHUNK_SIZE  8192


struct key
{
    size_t  start;          /* starting index from which the corresponding value can compute a given seed */
    size_t  end;            /* ending index at the end of which the corresponding value can compute a given seed */

    bool operator<(const key &k) const {
        return start < k.start || end < k.end;
    }
    bool operator==(const key &k) const {
        return start == k.start && end == k.end;
    }
};

struct value
{
    int     height;
    size_t  index;
    uint8_t parent_node[SEED_SIZE];
};

typedef std::map<key,value> DS;

struct secret_key
{
    /* data */
    uint8_t y[32];        /* private key */
    uint8_t x_0[32];      /* root of seed tree */
    uint8_t r_0[32];      /* root of seed tree */
    uint8_t x_i[32];      /* current leaf in the seed tree */
    uint8_t s_A[32];      /* aggregated signature */
    size_t i;             /* epoch counter */
    int j;                /* iteration counter for the given epoch "i" */
};

struct signature
{
    /* data */
    uint8_t s[32];          /* signature */
    size_t i;               /* epoch counter */
};


struct public_key
{
    /* data */
    point_t Y;               /* public key */
    DS X_i;                  /* map of disclosed seeds */
    uint8_t s_A[32];         /* aggregated signature */
    point_t R[8192];         /* public commitments */
    point_t R1[8192];         /* public commitments */
    point_t R2[8192];         /* public commitments */
    point_t R3[8192];         /* public commitments */
    point_t R4[8192];         /* public commitments */
    point_t R_A;             /* product of the public ephemeral keys that corresponds to valid signatures */
    std::map<size_t, signature> failed_sigs; /* list of failed signatures */
    std::map<size_t, int> failed_indices; /* list of failed items' indices */
};

#endif
