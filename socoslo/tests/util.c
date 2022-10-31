
#ifndef UTIL_H
#define UTIL_H


#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <cstring>
#include <string.h>
#include "time.h"
#include <openssl/rand.h>
#include <openssl/sha.h>

/*
 *  Function:       sha256_i: 
 *
*/
int sha256_i(uint8_t* msg, size_t msglen,
             uint8_t* hash, int counter)
{
    uint8_t prior_hash[msglen + sizeof(counter)];

    memset(prior_hash, sizeof(prior_hash), 0);
    memcpy(prior_hash, msg, msglen);
    memcpy(prior_hash + msglen, (uint8_t*) &counter, sizeof(counter));

    if (NULL == SHA256(prior_hash, sizeof(prior_hash), hash))                                 { return 0; }

    return 1;
}


/*
 *  Function:       print_hex: 
 *
*/
void print_hex(unsigned char* arr, int len)
{
    int i;
    printf("\n");
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
    printf("\n");
}


/*
 *  Function:       print_hex_m: 
 *
*/
void print_hex_m(char *m, unsigned char* arr, int len)
{
    int i;
    printf("%s\n", m);
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
    printf("\n");
}


/*
 *  Function:       write2file: 
 *
*/
void write2file(char *path2file, char *data, size_t datalen)
{
    std::ofstream output_file;

    output_file.open(path2file);
    output_file.write((char*) data, datalen);
    output_file.close();
}


/*
 *  Function:       read4file: 
 *
*/
void read4file(char *path2file, char *data, size_t datalen)
{
    std::ifstream input_file;

    input_file.open(path2file);
    input_file.read(data, datalen);
    input_file.close();
}


/*
 *  Function:       mapint2file: 
 *
*/
void mapint2file(std::map<size_t, int> data, char *path2file) {
    std::ofstream   output_file; 
    size_t          k;
    int             v;
    std::map<size_t, int> data_tmp;


    output_file.open(path2file);
    for (const auto& p : data) {
        output_file << p.first << std::endl;
        output_file << p.second << std::endl;
    }
    output_file.close();
}


/*
 *  Function:       mapsig2file: 
 *
*/
void mapsig2file(std::map<size_t, signature> data, char *path2file) {
    std::ofstream               output_file;

    output_file.open(path2file);
    for (const auto& p : data) {
        output_file.write((char*) &p.first, sizeof(size_t));
        output_file.write((char*) &p.second, sizeof(signature));
    }
    output_file.close();
}


/*
 *  Function:       mapseed2file: 
 *
*/
void mapseed2file(std::map<key, value> data, char *path2file) {
    std::ofstream               output_file;

    output_file.open(path2file);
    for (const auto& p : data) {
        output_file.write((char*) &p.first, sizeof(key));
        output_file.write((char*) &p.second, sizeof(value));
    }
    output_file.close();
}


/*
 *  Function:       file2mapint: 
 *
*/
void file2mapint(std::map<size_t, int> *data, char *path2file) {
    std::ifstream   input_file;
    size_t          k;
    int             v;
    std::map<size_t, int> data_tmp;


    input_file.open(path2file);
    while (input_file >> k >> v) {
        data_tmp[k] = v;
    }
    input_file.close();
    *data = data_tmp;
}


/*
 *  Function:       file2mapsig: 
 *
*/
void file2mapsig(std::map<size_t, signature> *data, char *path2file) {
    std::ifstream   input_file;
    size_t          k;
    signature       v;
    std::map<size_t, signature> data_tmp;

    input_file.open(path2file);
    while (input_file) {
        input_file.read((char*) &k, sizeof(k));
        input_file.read((char*) &v, sizeof(v));
        data_tmp[k] = v;
    }

    input_file.close();
    *data = data_tmp;
}

/*
 *  Function:       file2mapseed: 
 *
*/
void file2mapseed(std::map<key, value> *data, char *path2file) {
    std::ifstream   input_file;
    key             k;
    value           v;
    std::map<key, value> data_tmp;

    input_file.open(path2file);
    while (input_file.good()) {
        input_file.read((char*) &k, sizeof(k));
        input_file.read((char*) &v, sizeof(v));

        data_tmp[k] = v;
    }

    input_file.close();
    *data = data_tmp;
}


/*
 *  Function:       printMap: 
 *
*/
template<typename Map>
void printMap(const Map& map, char *title) {
    std::cout << title << "\n";
    for (const auto& p : map)
        std::cout<<p.first <<","<< p.second <<std::endl;
}


/*
 *  Function:       setup_params: 
 *
*/
void setup_params(char *path2log, size_t *sct_l1, size_t *sct_l2, double *tau_F){
    size_t              l1, l2;
    double              t_f;
    std::ifstream       log_file;


    printf("******** Selection of the system parameters ********\n");
    printf("Choose the path to the log files:  ");
    while (1) {
        std::cin >> path2log;
        log_file.open(path2log);
        if (!log_file.is_open()) printf("\nERROR: path for logs is invalid!\nPlease try again: ");
        else break;
    }
    printf("Select the number of epochs (SCT_L1):  ");
    while (1) {
        std::cin >> l1;
        if (l1 < 1)    printf("\nERROR: L1 should be a positive integer!\nPlease try again: ");
        else            break;
    }
    printf("Select the number of iterations per epoch (SCT_L2):  ");
    while (1) {
        std::cin >> l2;
        if (l2 < 1)     printf("\nERROR: L2 should be a positive integer!\nPlease try again: ");
        else            break;
    }
    printf("Select the failure rate (T_F):  ");
    while (1) {
        std::cin >> t_f;
        if (t_f < 0 || t_f >1) printf("\nERROR: T_F rate should be comprised between 0 and 1!\nPlease try again: ");
        else break;
    }
    std::cout << "\n";

    *sct_l1 = l1;
    *sct_l2 = l2;
    *tau_F = t_f;
}


/*
 *  Function:       save_pk: 
 *
*/
void save_pk(char *root_path, public_key pk)
{
    char pk_path[100] = { 0 };


    memset(pk_path, 0, sizeof(pk_path));
    sprintf(pk_path, "%s/pk/Y", root_path);
    write2file(pk_path, (char*) &pk.Y, sizeof(pk.Y));
    sprintf(pk_path, "%s/pk/s_A", root_path);
    write2file(pk_path, (char*) pk.s_A, sizeof(pk.s_A));
    sprintf(pk_path, "%s/pk/R_A", root_path);
    write2file(pk_path, (char*) pk.R_A, sizeof(pk.R_A));
    sprintf(pk_path, "%s/pk/failed_indices", root_path);
    mapint2file(pk.failed_indices, pk_path);
    sprintf(pk_path, "%s/pk/failed_sigs", root_path);
    mapsig2file(pk.failed_sigs, pk_path);
    sprintf(pk_path, "%s/pk/seeds", root_path);
    mapseed2file(pk.X_i, pk_path);
}


/*
 *  Function:       setup_server_params: 
 *
*/
void setup_server_params(char *path2log, size_t *sct_l1, size_t *sct_l2){
    size_t              l1, l2;
    double              t_f;
    std::ifstream       log_file;


    printf("******** Selection of the system parameters ********\n");
    printf("Choose the path to the log files:  ");
    while (1) {
        std::cin >> path2log;
        log_file.open(path2log);
        if (!log_file.is_open()) printf("\nERROR: path for logs is invalid!\nPlease try again: ");
        else break;
    }
    printf("Select the number of epochs (SCT_L1):  ");
    while (1) {
        std::cin >> l1;
        if (l1 < 1)    printf("\nERROR: L1 should be a positive integer!\nPlease try again: ");
        else            break;
    }
    printf("Select the number of iterations per epoch (SCT_L2):  ");
    while (1) {
        std::cin >> l2;
        if (l2 < 1)     printf("\nERROR: L2 should be a positive integer!\nPlease try again: ");
        else            break;
    }
    std::cout << "\n";

    *sct_l1 = l1;
    *sct_l2 = l2;
}


/*
 *  Function:       read_pk: 
 *
*/
void read_pk(char *root_path, public_key *pk)
{
    char pk_path[100] = { 0 };


    sprintf(pk_path, "%s/pk/Y", root_path);
    read4file(pk_path, (char*) pk->Y, sizeof(pk->Y));

    sprintf(pk_path, "%s/pk/s_A", root_path);
    read4file(pk_path, (char*) pk->s_A, sizeof(pk->s_A));
    
    sprintf(pk_path, "%s/pk/R_A", root_path);
    read4file(pk_path, (char*) pk->R_A, sizeof(pk->R_A));

    sprintf(pk_path, "%s/pk/failed_indices", root_path);
    file2mapint(&pk->failed_indices, pk_path);
    
    sprintf(pk_path, "%s/pk/failed_sigs", root_path);
    file2mapsig(&pk->failed_sigs, pk_path);
    
    sprintf(pk_path, "%s/pk/seeds", root_path);
    file2mapseed(&pk->X_i, pk_path);
}


#endif
