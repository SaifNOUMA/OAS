
#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "test_extras.h"
#include "time.h"

#include "conf.h"
#include "util.c"
#include "tree_util.c"
#include "fiposa_util.c"
#include "fiposa-scheme.c"


using namespace std;


int main(int argc, char *argv[])
{
    ECCRYPTO_STATUS         status;
    ifstream                output_file, seed_file;
    struct public_key       pk;
    key                     k;
    value                   v;
    static DS               Xi;
    int                     audit_valid = 0;
    double                  audit_ver = 0.0;
    clock_t                 t0, t1;
    size_t                  SCT_L1, SCT_L2, SCT_T, CHUNK_SIZE, T_f, freq, rem;

    SCT_L1      = atoi(argv[1]);
    SCT_L2      = atoi(argv[2]);
    SCT_T       = (1 << SCT_L1) * SCT_L2;
    CHUNK_SIZE  = SCT_L2 * 32;
    T_f         = SCT_T * 0.01;
    freq        = T_f / 3;
    rem         = T_f % 3;

    char root_path[100] = { 0 };
    sprintf(root_path, "data/depth_%ld", SCT_L1);


    // ------------------------------------------------------------------------------------------------------------------------------------------------
    char pk_path[100] = { 0 };
    printf("INFO:  Data reading (public key, seeds) is about to start ...\n");
    // Reading the public key and the map of the seeds

    sprintf(pk_path, "%s/pk/Y", root_path);
    read4file(pk_path, (char*) pk.Y, sizeof(pk.Y));

    sprintf(pk_path, "%s/pk/s_A", root_path);
    read4file(pk_path, (char*) pk.s_A, sizeof(pk.s_A));
    
    sprintf(pk_path, "%s/pk/R_A", root_path);
    read4file(pk_path, (char*) pk.R_A, sizeof(pk.R_A));

    sprintf(pk_path, "%s/pk/failed_indices", root_path);
    file2mapint(&pk.failed_indices, pk_path);
    
    sprintf(pk_path, "%s/pk/failed_sigs", root_path);
    file2mapsig(&pk.failed_sigs, pk_path);
    
    sprintf(pk_path, "%s/pk/seeds", root_path);
    file2mapseed(&pk.X_i, pk_path);
    
    printf("INFO:  Reading (public key, seeds) was successfully done.\n");
    // ------------------------------------------------------------------------------------------------------------------------------------------------


    // ------------------------------------------------------------------------------------------------------------------------------------------------
    printf("\nINFO:  Auditor investigation is about to start ...\n");
    for (int i = 0 ; i < 100 ; i++) {
        t0 = clock();
        if (ECCRYPTO_SUCCESS != (status = FOPAS_AuditVer(pk, 1 << SCT_L1, SCT_L1, SCT_L2, &audit_valid, (char*) "../../fopas/FourQ_64bit_and_portable/data/logs.txt")))
        {
            printf("ERROR: AVer failed !\n");
            return 1;
        }
        t1 = clock();
        audit_ver += (double) (t1-t0) / CLOCKS_PER_SEC;
    }
    if (audit_valid == 0) {
        printf("INFO:  Audit verification successfully finished in %.2fs\n", audit_ver / 100);
    } else {
        printf("ERROR: Audit verification failed!\n");
        return 1;
    }
    // ------------------------------------------------------------------------------------------------------------------------------------------------


    goto cleanup;

error:
    return 1;
cleanup:
    return 0;
}
