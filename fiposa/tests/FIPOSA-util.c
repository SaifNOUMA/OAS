

#ifndef TREE_UTIL_H
#define TREE_UTIL_H


#include "util.c"
#include "conf.h"


/*
 *  Function:       seed_traverse: 
 *
 * root             root of the subtree
 * h_0              height of the root in the global seed tree
 * i_0              index of the root in the global seed tree
 * x_hi             requested seed
 * h                height of the requested seed
 * i                index of the requested seed
 * 
*/
ECCRYPTO_STATUS seed_traverse(uint8_t *root, int h_0, size_t i_0,
                              uint8_t *x_hi, int h, size_t i)
{
    int     j, depth, index, start_index, coverage;
    uint8_t x0[SEED_SIZE], xp[SEED_SIZE];


    if (h_0 == h && i_0 == i) {
        memmove(x_hi, root, SEED_SIZE);
        return ECCRYPTO_SUCCESS;
    }

    depth       = h - h_0;
    coverage    = 1 << depth;
    start_index = 1;
    index       = i - (i_0 - 1) * (1 << depth);
    memmove(xp, root, SEED_SIZE);

    for (j = 1 ; j <= depth - 1 ; j++) {
        coverage = coverage / 2;

        if (index < start_index + coverage) {
            if (ECCRYPTO_ERROR == sha256_i(xp, SEED_SIZE, xp, 0))                                      { return ECCRYPTO_ERROR; }
        } else {
            if (ECCRYPTO_ERROR == sha256_i(xp, SEED_SIZE, xp, 1))                                      { return ECCRYPTO_ERROR; }
            start_index += coverage;
        }
    }
    if (start_index == index) {
        if (ECCRYPTO_ERROR == sha256_i(xp, SEED_SIZE, xp, 0))                                          { return ECCRYPTO_ERROR; }
    } else {
        if (ECCRYPTO_ERROR == sha256_i(xp, SEED_SIZE, xp, 1))                                          { return ECCRYPTO_ERROR; }
    }
    memmove(x_hi, xp, SEED_SIZE);


    return ECCRYPTO_SUCCESS;
}


/*
 *  Function:       seed_optimizer: 
 *
 * 
 * root             root the seed tree
 * i                leaf index
 * X_i              DS structure that contains the needed nodes to iterate through the leafs until we reach the leaf index "i"
 * 
*/
ECCRYPTO_STATUS seed_optimizer(uint8_t *root, size_t i, DS *X_i, size_t depth)
{
    int                     displacement = 0, start_index, end_index, h, i_h;
    uint8_t                 xh[SEED_SIZE];
    struct key              k;
    struct value            v;
    DS                      X_ds;
    std::bitset<30>         I(i);
    

    for (int index = depth ; index >= 0 ; index--) {
        if (I[index]) {
            k.start     = displacement + 1;
            k.end       = displacement + (1 << index);
            v.height    = depth - index;
            v.index     = (displacement / (1 << index)) + 1;
            seed_traverse(root, 0, 1, xh, v.height, v.index);
            memmove(v.parent_node, xh, SEED_SIZE);
            X_ds.insert( { k , v } );
            displacement += (1 << index);
        }
    }
    *X_i = X_ds;


    return ECCRYPTO_SUCCESS;
}



/*
 *  Function:       retieve_seed: 
 *
 * 
 * root             root the seed tree
 * i                leaf index
 * X_i              DS structure that contains the needed nodes to iterate through the leafs until we reach the leaf index "i"
 * 
*/
ECCRYPTO_STATUS retrieve_seed(uint8_t *seed, size_t i, DS X_i, size_t depth)
{
    key k;
    value v;
    uint8_t xi[SEED_SIZE];

    for (auto it = X_i.cbegin() ; it != X_i.cend() ; ++it ) {
        k = it->first;
        v = it->second;
        if (k.start <= i && k.end >= i) {
            if (ECCRYPTO_ERROR == seed_traverse(v.parent_node, v.height, v.index, xi, depth, i))   { return ECCRYPTO_ERROR; }
            break;
        }
    }
    memmove(seed, xi, SEED_SIZE);


    return ECCRYPTO_SUCCESS;
}

#endif
