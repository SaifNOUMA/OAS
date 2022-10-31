
#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "time.h"
#include "conf.h"
#include "util.c"
#include "SOCOSLO-util.c"
#include "SOCOSLO-app.c"
#include "SOCOSLO-sgn.c"


using namespace std;


int main(int argc, char *argv[])
{
    ECCRYPTO_STATUS status;
    public_key      pk;
    int             audit_valid = 0;
    double          audit_ver = 0.0;
    clock_t         t0, t1;
    size_t          SCT_L1, SCT_L2, SCT_T, CHUNK_SIZE;
    char            root_path[100] = {0}, path2log[100] = {0};


    setup_server_params(path2log, &SCT_L1, &SCT_L2);                     /* get the system-wide parameters from the user input */
    SCT_T       = (1 << SCT_L1) * SCT_L2;
    CHUNK_SIZE  = SCT_L2 * 32;

#ifdef INFO
    printf("INFO:  Data reading (public key, seeds) is about to start ...\n");
#endif
    sprintf(root_path, "data/depth_%ld", SCT_L1);                       /* reading the public key from memory */
    read_pk(root_path, &pk);
#ifdef INFO
    printf("INFO:  Reading (public key, seeds) was successfully done.\n");
    printf("\nINFO:  Verifier investigation is about to start ...\n");
#endif
    for (int i = 0 ; i < 100 ; i++) {
        t0 = clock();                                                   /* perform batch verification for the set of log entries */
        if (ECCRYPTO_SUCCESS != (status = SOPAS_sebver(pk, 1 << SCT_L1, SCT_L1, SCT_L2, &audit_valid, path2log)))
        {
#ifdef INFO
            printf("INFO: Batch verification was failed!\n");
#endif
            goto error;
        }
        t1 = clock();
        audit_ver += (double) (t1-t0) / CLOCKS_PER_SEC;
    }
#ifdef INFO
    if (audit_valid == 0) {
        printf("INFO:  Selective batch verification successfully finished in %.2fs\n", audit_ver / 100);
#endif
    } else {
#ifdef INFO
        printf("INFO:  Selective Batch verification failed!\n");
#endif
        return 1;
    }
    // ------------------------------------------------------------------------------------------------------------------------------------------------


    goto cleanup;

error:
    printf("INFO:  Task completed with failure!\n");
    return 1;
cleanup:
    printf("INFO:  Task completed successfully.\n");
    return 0;
}
