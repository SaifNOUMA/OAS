
#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "conf.h"
#include "util.c"
#include "FIPOSA-util.c"
#include "FIPOSA-app.c"
#include "FIPOSA-sgn.c"


using namespace std;


int main(int argc, char *argv[])
{
    ECCRYPTO_STATUS     status;
    public_key          pk;
    int                 audit_valid = 0;
    double              audit_ver = 0.0;
    clock_t             t0, t1;
    size_t              SCT_L1, SCT_L2, SCT_T, CHUNK_SIZE;
    char                root_path[100] = {0}, path2log[100] = {0};


    setup_audit_params(path2log, &SCT_L1, &SCT_L2);                     /* get the system-wide parameters from the user input */
    SCT_T       = (1 << SCT_L1) * SCT_L2;
    CHUNK_SIZE  = SCT_L2 * 32;

#ifdef INFO
    printf("INFO:  Data reading (public key, seeds) is about to start ...\n");
#endif
    sprintf(root_path, "data/depth_%ld", SCT_L1);                       /* reading the public key from memory */
    read_pk(root_path, &pk);   
#ifdef INFO
    printf("INFO:  Reading (public key, seeds) was successfully done.\n");
    printf("\nINFO:  Auditor investigation is about to start ...\n");
#endif

    for (int i = 0 ; i < 100 ; i++) {
        t0 = clock();                                                   /* perform auditing for the set of log entries */
        if (ECCRYPTO_SUCCESS != (status = FIPOSA_AuditVer(pk, 1 << SCT_L1, SCT_L1, SCT_L2, &audit_valid, path2log)))
        {
            printf("ERROR: AVer failed !\n");
            return 1;
        }
        t1 = clock();
        audit_ver += (double) (t1-t0) / CLOCKS_PER_SEC;
    }
    if (audit_valid == 0) {
#ifdef INFO
        printf("INFO:  Audit verification successfully finished in %.2fs\n", audit_ver / 100);
#endif
    } else {
#ifdef INFO
        printf("INFO:  Audit verification failed!\n");
#endif
        goto error;
    }


    goto cleanup;

error:
    printf("INFO:  Task completed with failure!\n");
    return 1;
cleanup:
    printf("INFO:  Task completed successfully.\n");
    return 0;
}
