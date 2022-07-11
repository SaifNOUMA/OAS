
#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../FourQ.h"
#include "test_extras.h"
#include "time.h"

#include "conf.h"
#include "util.c"
#include "tree_util.c"
#include "socosa_util.c"
#include "socosa-scheme.c"
#include <string.h>

using namespace std;


int main(int argc, char *argv[])
{
    ECCRYPTO_STATUS         status;
    ifstream                log_file, sig_file, input_file;
    ofstream                output_file, pk_file, mapseed_file;
    size_t                  SCT_L1, SCT_L2, SCT_T, CHUNK_SIZE, T_f, freq, rem, frequency = 0;
    double                  tau_F;

    SCT_L1      = atoi(argv[1]);
    SCT_L2      = atoi(argv[2]);
    tau_F       = atof(argv[3]);
    SCT_T       = (1 << SCT_L1) * SCT_L2;
    CHUNK_SIZE  = SCT_L2 * 32;
    T_f         = (1 << SCT_L1) * tau_F;

    static public_key       pk;
    secret_key              sk;
    signature               sig[SCT_L2], sig_v;
    static DS               X_i, Xi_arr[(1 << 25)];
    uint8_t                 msg[CHUNK_SIZE];
    int                     valid[SCT_L2], valid_v, audit_valid = 0;
    double                  audit_ver = 0.0, sign_time = 0.0, ver_time = 0.0, distill_time = 0.0;
    size_t                  epoch, iter, failed_items = 0;
    clock_t                 t0, t1;


    char root_path[100] = { 0 };
    sprintf(root_path, "data/depth_%ld", SCT_L1);

    // ------------------------------------------------------------------------------------------------------------------------------------------------
    // Key generation of the private/public keys, along with the set of messages
    if (ECCRYPTO_SUCCESS != (status = SOPAS_kg(&sk, &pk, SCT_L1, SCT_L2))) {
        printf("ERROR: KeyGen failed!\n");
        return 1;
    }
    printf("FOPAS Key Generation Completed!\n");

    // Read the audit logs
    log_file.open("../../fopas/FourQ_64bit_and_portable/data/logs.txt");
    if (!log_file.is_open()) {
        printf("ERROR: Data load failed!\n");
        return 1;
    }
    // ------------------------------------------------------------------------------------------------------------------------------------------------


    // ------------------------------------------------------------------------------------------------------------------------------------------------
    // Signature generation of the audit logs
    printf("\nINFO:  Signature generation phase is about to start ...\n");

    char sig_path[100] = { 0 };
    sprintf(sig_path, "%s/sig.txt", root_path);

    output_file.open(sig_path);
    for (epoch = 0 ; epoch < (1 << SCT_L1) ; epoch++) {
        // Load the audit logs for the corresponding epoch
        log_file.read((char*) msg, CHUNK_SIZE);

        // Signature generation for the current epoch's messages
        for (iter = 0 ; iter < SCT_L2 ; iter++) {
            t0 = clock();
            if (ECCRYPTO_SUCCESS != (status = SOPAS_Sign(&sk, SCT_L1, SCT_L2,
                                                        msg + iter * MSG_SIZE, &sig[iter], &Xi_arr[epoch])))
            {
                printf("ERROR: Signature generation failed in iteration %ld, epoch %ld!\n", iter+1, epoch);
                return 1;
            }
            t1 = clock();
            sign_time += (double) (t1 - t0);
        }
        output_file.write((char*) &sig[SCT_L2-1], sizeof(signature));

        if ((epoch + 1) % (1024 * 16) == 0) {
            printf("INFO:  Sig gen reaches epoch %.8ld [average time = %.2fus]\n", epoch, (sign_time * 1000 * 1000) / (CLOCKS_PER_SEC * (epoch+1) * SCT_L2));
        }
    }
    printf("INFO:  Signature generation successfully finished in %.2fs\n", sign_time / CLOCKS_PER_SEC );
    printf("INFO:  Average sig gen time = %.2fus\n", (sign_time * 1000 * 1000) / (CLOCKS_PER_SEC * SCT_T));
    log_file.close();
    output_file.close();
    // ------------------------------------------------------------------------------------------------------------------------------------------------


    // ------------------------------------------------------------------------------------------------------------------------------------------------
    printf("\nINFO:  Signature verification phase is about to start ...\n");
    log_file.open("../../fopas/FourQ_64bit_and_portable/data/logs.txt");
    sig_file.open(sig_path);

    for (epoch = 0 ; epoch < (1 << SCT_L1) ; epoch++) {
        // Load the audit logs and the signatures for the corresponding epoch
        log_file.read((char*) msg, CHUNK_SIZE);
        sig_file.read((char*) &sig_v, sizeof(signature));
        
        if (frequency <= T_f) {
            frequency ++;
            sig_v.s[0] ++;
        }

        // verify the signatures of the given epoch
        t0 = clock();
        if (ECCRYPTO_SUCCESS != (status = SOPAS_Ver(&pk, SCT_L1, SCT_L2, msg, Xi_arr[epoch], sig_v, &valid[SCT_L2-1])))
        {
            printf("ERROR: Ver failed for the epoch [%ld]!\n", sig[iter].i);
            return 1;
        }
        t1 = clock();
        ver_time += (t1 - t0);

        // distill the signatures of the given epoch
        t0 = clock();
        if (ECCRYPTO_SUCCESS != (status = SOPAS_Distill(&pk, SCT_L2, sig_v, valid[SCT_L2-1])))
        {
            printf("ERROR: Distillation failed for the epoch [%ld]!\n", sig[iter].i);
            return 1;
        }
        t1 = clock();
        distill_time += (t1 - t0);

        if ((epoch + 1) % (1024 * 16) == 0) {
            printf("INFO:  Sig ver reaches epoch %.8ld [average time = %.2fms]\n", epoch+1, (ver_time * 1000) / (CLOCKS_PER_SEC * (epoch+1)));
            printf("INFO:  Dsitill reaches epoch %.8ld [average time = %.2fms]\n\n", epoch+1, (distill_time * 1000) / (CLOCKS_PER_SEC * (epoch+1)));
        }
    }
    log_file.close();
    sig_file.close();

    printf("INFO:  Signature verification (for T messages) successfully finished in %.2fs\n", ver_time / CLOCKS_PER_SEC);
    printf("INFO:  Average verification time (per epoch) = %.2fms\n", (ver_time * 1000) / (CLOCKS_PER_SEC * (1 << SCT_L1)) );
    printf("INFO:  Failure rate = %.2f%\n", (double) (pk.failed_indices.size() * 100.0) / ((1 << SCT_L1) * 1.0) );
    printf("INFO:  #failed items = %ld\n\n", pk.failed_indices.size());
    printf("INFO:  Distillation phase successfully finished in %.2fs\n", distill_time / CLOCKS_PER_SEC);
    // ------------------------------------------------------------------------------------------------------------------------------------------------



    // ------------------------------------------------------------------------------------------------------------------------------------------------
    char pk_path[100] = { 0 };
    printf("\nINFO:  Saving the public key for audit verification ...\n");

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

    printf("\nINFO:  Saving the public key successfully finished.\n");
    // // ------------------------------------------------------------------------------------------------------------------------------------------------

    printf("\nINFO:  Auditor investigation is about to start ...\n");
    t0 = clock();
    if (ECCRYPTO_SUCCESS != (status = SOPAS_AuditVer(pk, 1 << SCT_L1, SCT_L1, SCT_L2, &audit_valid, (char*) "../../fopas/FourQ_64bit_and_portable/data/logs.txt")))
    {
        printf("ERROR: AVer failed !\n");
        return 1;
    }
    t1 = clock();
    audit_ver = (double) (t1-t0) / CLOCKS_PER_SEC;
    if (audit_valid == 0) {
        printf("INFO:  Audit verification successfully finished in %.2fs\n", audit_ver);
    } else {
        printf("ERROR: Audit verification failed!\n");
        return 1;
    }


    goto cleanup;

error:
    return 1;
cleanup:
    return 0;
}
