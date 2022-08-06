
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <string>
#include <time.h>
#include <openssl/rand.h>
#define NUM_CHUNKS 128


using namespace std;

int main (int argc, char *argv[])
{
    static uint8_t logdata[1000000000L];
    char*       path2outfile;
    size_t      outfile_len;
    double      gen_time = 0.0, store_time = 0.0;
    clock_t     t0, t1;
    ofstream    output_file;


    outfile_len = atoi(argv[1]);
    path2outfile = argv[2];
    output_file.open(path2outfile);
    for (int chunk = 0 ; chunk < outfile_len ; chunk++) {
        t0 = clock();
        if (0 == RAND_bytes(logdata, sizeof(logdata))) {
            printf("ERROR: Data generation failed");
        }
        t1 = clock();
        gen_time += (double) (t1-t0);

        t0 = clock();
        for (size_t i = 0 ; i < sizeof(logdata) ; i++) {
            output_file << (int) logdata[i] % 10;
        }
        t1 = clock();
        store_time += (double) (t1-t0);
    }
    output_file.close();

    printf("DEBUG: Data generation passed successfully in %.2f s.\n", ((double) (gen_time)) / (CLOCKS_PER_SEC) );
    printf("DEBUG: Storing audit data passed successfully in %.2f s.\n", ((double) (store_time)) / (CLOCKS_PER_SEC) );


   return 0; 
}
