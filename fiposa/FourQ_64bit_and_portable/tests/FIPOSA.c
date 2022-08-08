#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "time.h"
#include "conf.h"
#include "util.c"
#include "FIPOSA-util.c"
#include "FIPOSA-app.c"
#include "FIPOSA-sgn.c"
#include <string.h>


using namespace std;


int main(int argc, char *argv[])
{
    ECCRYPTO_STATUS status;
    char            path2log[100], root_path[100] = { 0 }, sig_path[100] = { 0 }, pk_path[100] = { 0 };
    size_t          SCT_L1, SCT_L2, SCT_T, CHUNK_SIZE, T_f, counter = 0, epoch, iter;
    double          tau_F, sign_t = 0.0, ver_t = 0.0, audit_t = 0.0, distill_t = 0.0;
    clock_t         t0, t1;
    ifstream        log_file, sig_file;
    ofstream        out_file;
    public_key      pk;
    secret_key      sk;
    static DS       X_i, Xi_arr[(1 << 22)];
    setup_params(path2log, &SCT_L1, &SCT_L2, &tau_F);                   /* get the system-wide parameters from the user input */
    SCT_T           = (1 << SCT_L1) * SCT_L2;
    CHUNK_SIZE      = SCT_L2 * 32;
    T_f             = SCT_T * tau_F;

    int             valid[SCT_L2], audit_valid = 0;
    uint8_t         msg[CHUNK_SIZE];
    signature       sig[SCT_L2];

    sprintf(root_path, "data/depth_%ld", SCT_L1);
    if (ECCRYPTO_SUCCESS != (status = FIPOSA_kg(&sk, &pk))) {            /* key generation phase */
        printf("ERROR: key generation finished with failure!\n");
        goto error;
    }
#ifdef INFO
    printf("INFO:  key generation Completed.\n");
    printf("\nINFO:  Signature generation is about to start ...\n");
#endif
    sprintf(sig_path, "%s/sig.txt", root_path);
    out_file.open(sig_path);
    log_file.open(path2log);
    for (epoch = 0 ; epoch < (1 << SCT_L1) ; epoch++) {
        log_file.read((char*) msg, CHUNK_SIZE);                         /* load the logs for the i^th epoch */
        for (iter = 0 ; iter < SCT_L2 ; iter++) {
            t0 = clock();
            if (ECCRYPTO_SUCCESS != (status = FIPOSA_Sign(&sk, SCT_L1, SCT_L2,
                                                         msg + iter * MSG_SIZE, &sig[iter], &Xi_arr[epoch])))
            {
#ifdef INFO
                printf("ERROR:  Signature generation failed during the %ldth iteration in %ldth epoch!\n", iter+1, epoch);
#endif
                goto error;
            }
            t1 = clock();
            sign_t += (double) (t1 - t0);
        }
        out_file.write((char*) sig, SCT_L2 * sizeof(signature));

#ifdef INFO
        if ((epoch + 1) % 16384 == 0) {                                 /* debug the verification process */
            printf("INFO:  Sig gen reaches the %.8ld epoch [average time = %.2fus]\n", epoch, (sign_t * 1000 * 1000) / (CLOCKS_PER_SEC * (epoch+1) * SCT_L2));
        }
#endif
    }

    log_file.close();
    out_file.close();
#ifdef INFO
    printf("INFO:  Signature generation (for T messages) successfully finished in %.2fs\n", sign_t / CLOCKS_PER_SEC );
    printf("INFO:  Average signing time (per message) = %.2fus\n", (sign_t * 1000 * 1000) / (CLOCKS_PER_SEC * SCT_T));

    printf("\nINFO:  Signature verification is about to start ...\n");
#endif
    log_file.open(path2log);
    sig_file.open(sig_path);
    for (epoch = 0 ; epoch < (1 << SCT_L1) ; epoch++) {
        log_file.read((char*) msg, CHUNK_SIZE);                         /* load the logs for the i^th epoch */
        sig_file.read((char*) sig, SCT_L2 * sizeof(signature));         /* load the signatures for the i^th epoch */
        
        for (iter = 0 ; iter < SCT_L2 && counter < T_f ; iter++) {      /* invalidate signatures according to the failure rate */
            counter ++;
            sig[iter].s[0] ++;
        }

        t0 = clock();                                                   /* verify the signatures in the i^th epoch */
        if (ECCRYPTO_SUCCESS != (status = FIPOSA_Ver(&pk, SCT_L1, SCT_L2, msg, Xi_arr[epoch], sig, valid)))
        {
#ifdef INFO
            printf("ERROR: Ver failed for the epoch [%ld]!\n", sig[0].i);
#endif
            goto error;
        }
        t1 = clock();
        ver_t += (t1 - t0);

        t0 = clock();                                                   /* distill the signatures of the i^th epoch */
        if (ECCRYPTO_SUCCESS != (status = FIPOSA_Distill(&pk, SCT_L2, sig, valid)))
        {
#ifdef INFO
            printf("ERROR: Distillation failed for the epoch [%ld]!\n", sig[0].i);
#endif
            goto error;
        }
        t1 = clock();
        distill_t += (t1 - t0);

#ifdef INFO
        if ((epoch + 1) % 16384 == 0) {                                 /* debug the verification process */
            printf("INFO:  Sig ver reaches epoch %.8ld [average time = %.2fms]\n", epoch+1, (ver_t * 1000) / (CLOCKS_PER_SEC * (epoch+1)));
            printf("INFO:  Dsitill reaches epoch %.8ld [average time = %.2fms]\n\n", epoch+1, (distill_t * 1000) / (CLOCKS_PER_SEC * (epoch+1)));
        }
#endif
    }
    log_file.close();
    sig_file.close();
#ifdef INFO
    printf("INFO:  Signature verification (for T messages) successfully finished in %.2fs\n", ver_t / CLOCKS_PER_SEC);
    printf("INFO:  Average verification time (per epoch) = %.2fms\n", (ver_t * 1000) / (CLOCKS_PER_SEC * (1 << SCT_L1)) );
    printf("INFO:  Failure rate = %.2f%%\n", (double) (pk.failed_indices.size() * 100.0) / (SCT_T * 1.0) );
    printf("INFO:  #failed items = %ld\n\n", pk.failed_indices.size());
    printf("INFO:  Distillation phase successfully finished in %.2fs\n", distill_t / CLOCKS_PER_SEC);
#endif
    save_pk(root_path, pk);
#ifdef INFO
    printf("INFO:  Saving the public key successfully finished.\n");

    printf("\nINFO:  Auditor investigation is about to start ...\n");
#endif
    t0 = clock();                                                       /* perform auditing for the whole log entries */
    if (ECCRYPTO_SUCCESS != (status = FIPOSA_AuditVer(pk, 1 << SCT_L1, SCT_L1, SCT_L2, &audit_valid, path2log)))
    {
        printf("ERROR: AVer failed !\n");
        goto error;
    }
    t1 = clock();
    audit_t += (double) (t1-t0);

#ifdef INFO
    if (audit_valid == 0) {
        printf("INFO:  Audit verification successfully finished in %.2fs\n", audit_t / (CLOCKS_PER_SEC));
    } else {
        printf("ERROR: Audit verification failed!\n");
        goto error;
    }
#endif


    goto cleanup;

error:
    printf("INFO:  Task completed with failure!\n");
    return 1;
cleanup:
    printf("INFO:  Task completed successfully.\n");
    return 0;
}
