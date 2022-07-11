
#ifndef UTIL_H
#define UTIL_H


#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <ctime>
#include <cstring>


int sha256_i(uint8_t* message, size_t messagelen,
             uint8_t* hash, size_t counter)
{
    uint8_t prior_hash[messagelen + sizeof(counter)];

    memset(prior_hash, sizeof(prior_hash), 0);
    memcpy(prior_hash, message, messagelen);
    memcpy(prior_hash + messagelen, (uint8_t*) &counter, sizeof(counter));

    if (NULL == SHA256(prior_hash, sizeof(prior_hash), hash))                                 { return 0; }

    return 1;
}

void print_hex(unsigned char* arr, int len)
{
    int i;
    printf("\n");
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
    printf("\n");
}

void print_hex_m(char *m, unsigned char* arr, int len)
{
    int i;
    printf("%s\n", m);
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
    printf("\n");
}

void write2file(char *path2file, char *data, size_t datalen)
{
    std::ofstream output_file;

    output_file.open(path2file);
    output_file.write((char*) data, datalen);
    output_file.close();
}


void read4file(char *path2file, char *data, size_t datalen)
{
    std::ifstream input_file;

    input_file.open(path2file);
    input_file.read(data, datalen);
    input_file.close();
}


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


void mapsig2file(std::map<size_t, signature> data, char *path2file) {
    std::ofstream               output_file;

    output_file.open(path2file);
    for (const auto& p : data) {
        output_file.write((char*) &p.first, sizeof(size_t));
        output_file.write((char*) &p.second, sizeof(signature));
    }
    output_file.close();
}


void mapseed2file(std::map<key, value> data, char *path2file) {
    std::ofstream               output_file;

    output_file.open(path2file);
    for (const auto& p : data) {
        output_file.write((char*) &p.first, sizeof(key));
        output_file.write((char*) &p.second, sizeof(value));
    }
    output_file.close();
}


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


void file2mapsig(std::map<size_t, signature> *data, char *path2file) {
    std::ifstream   input_file;
    size_t          k;
    signature v;
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

template<typename Map>
void printMap(const Map& map, char *title) {
    std::cout << title << "\n";
    for (const auto& p : map)
    {
        std::cout<<p.first <<","<< p.second <<std::endl;
    }
}

#endif
