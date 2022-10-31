#ifndef CONF_H
#define CONF_H


#include <stdio.h>
#include <iostream>
#include <map>
#include <vector>
#include <bitset>

#define BENCH_LOOPS 10000
#define BPV_V       16
#define BPV_K       1024
#define MSG_SIZE    32
#define SEED_SIZE   32


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
    uint8_t y[32];          /* EC private key */
    uint8_t x_0[32];        /* SCT's root */
    uint8_t x_i[32];        /* current SCT's leaf */
    uint8_t r[BPV_K][32];   /* private ephemeral key */
    point_t R[BPV_K];       /* public ephemeral key */
    size_t i;               /* epoch counter */
    int j;                  /* iteration counter in the i^th epoch */
};

struct signature
{
    uint8_t s[32];          /* signature */
    point_t R;              /* public ephemeral key */
    size_t i;               /* epoch counter */
    int j;                  /* iteration counter */
};

struct public_key
{
    point_t Y;               /* EC public key */
    DS X_i;                  /* map of the disclosed seeds */
    uint8_t s_A[32];         /* aggregated signature */
    point_t R_A;             /* product of the public ephemeral keys for the valid signatures */
    std::map<size_t, signature> failed_sigs; /* list of failed signatures */
    std::map<size_t, int> failed_indices; /* list of failed items' indices */
};

#endif
