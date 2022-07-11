    // if (ECCRYPTO_ERROR == seed_optimizer(sk.x_0, 16, &X_i)) {
    //     printf("ERROR: Seed optimizer failed");
    //     return 1;
    // }

    // printf("DEBUG: sizeof(X_i [%d]) = [%ld]\n", 16, X_i.size());
    // for (auto it = X_i.cbegin() ; it != X_i.cend() ; ++it ) {
    //     key k = it->first;
    //     value v = it->second;

    //     printf("{ (%d,%d) -> (%d,%d) }\n", k.start, k.end, v.height, v.index);
    // }




    // // ------------------------------------------------------------------------------------------------------------------------
    // DS map;
    // if (ECCRYPTO_ERROR == seed_optimizer(sk.x_0, 8, &map)) {
    //     printf("ERROR: Seed optimizer failed");
    //     return 1;
    // }

    // uint8_t x1[SEED_SIZE], x8_1[SEED_SIZE], x8_2[SEED_SIZE];
    // if (ECCRYPTO_ERROR == seed_traverse(sk.x_0, 0, 1, x8_1, SCT_L1, 14)) { 
    //     std::cout << "ERROR: failed in traversing the seed tree\n";
    //     return 1;
    // }
    // if (ECCRYPTO_ERROR == seed_traverse(sk.x_0, 0, 1, x1, 1, 2)) { 
    //     std::cout << "ERROR: failed in traversing the seed tree\n";
    //     return 1;
    // }
    // if (ECCRYPTO_ERROR == seed_traverse(x1, 1, 2, x8_2, SCT_L1, 14)) { 
    //     std::cout << "ERROR: failed in traversing the seed tree\n";
    //     return 1;
    // }

    // retrieve_seed(x8_2, 8, map);
    

    // print_hex_m("A", x8_1, SEED_SIZE);
    // print_hex_m("B", x8_2, SEED_SIZE);
    

    // for (auto it = map.cbegin() ; it != map.cend() ; ++it ) {
    //     key k = it->first;
    //     value v = it->second;
    // }
    // // ------------------------------------------------------------------------------------------------------------------------



    // std::cout << "DEBUG [main]: \n";
    // for (iter = iter - SCT_L2 + 1 ; iter < iter - SCT_L2 + 1 + SCT_L2 ; iter++) {
    //     std::cout << valid[iter] << " ";
    // }
    // std::cout << "\n\n";


    // uint8_t tmp[32], A[64], B[64];
    // point_extproj_t Ae, A1;
    // point_extproj_precomp_t Apre;

    // memset(tmp, 0, 32);
    // tmp[0] = 2;

    // ecc_mul((point_affine*) pk.Y, (digit_t*) tmp, (point_affine*) A, false);

    // point_setup((point_affine*) pk.Y, Ae);
    // point_setup((point_affine*) pk.Y, A1);
    // R1_to_R2(A1, Apre);
    // eccadd(Apre, Ae);
    // eccnorm(Ae, (point_affine*) B);

    // if (0 == memcmp(A, B, 64)) {
    //     std::cout << "DEBUG: ecc mul/add are valid\n";
    // }

    // // ------------------------------------------------------------------------------------------------------------------------



    // cout << endl << endl;

    // uint8_t RA[64], r_a[32], z[64];
    // add_mod_order((digit_t*) sk.r[0], (digit_t*) sk.r[1], (digit_t*) r_a);
    // ecc_mul_fixed((digit_t*) r_a, (point_affine*) RA);
    // print_hex_m("ADD RA", RA, 64);

    // point_extproj_t         R1, R;
    // point_extproj_precomp_t R_tmp;

    // memset(z, 0, 64);


    // point_setup((point_affine*) z, R);
    
    // point_setup((point_affine*) sk.R[0], R1);
    // R1_to_R2(R1, R_tmp);
    // eccadd(R_tmp, R);

    // point_setup((point_affine*) sk.R[1], R1);
    // R1_to_R2(R1, R_tmp);
    // eccadd(R_tmp, R);

    // eccnorm(R, (point_affine*) RA);
    // print_hex_m("ADD RA", RA, 64);


    // // ------------------------------------------------------------------------------------------------------------------------
    // printf("\n\n");

    // uint8_t RA[64], r_A[32], rr[32], Rt[64];
    // point_t R_res, R_mul, Rr;

    // memmove(r_A, sig[0].r, 32);
    // memmove(Rr, sig[0].R, 64);


    // for (int i = 0 ; i < SCT_T ; i++) {
    //     ecc_mul_fixed((digit_t*) sig[i].r, R_res);
    //     if (memcmp(R_res, sig[i].R, 64)) {
    //         cout << "ERROR: keys does not match! [" << i  << "]\n";
    //         // return 1;
    //     }
    // }

    // int n;
    // cin >> n;



    // for (int i = 2 ; i < n ; i++) {
    //     memcpy(rr, sig[i].r, 32);
    //     add_mod_order((digit_t*) r_A, (digit_t*) rr, (digit_t*) r_A);
    
    //     point_extproj_t         R1, R;
    //     point_extproj_precomp_t R_tmp;
    //     point_setup(Rr, R);
    //     R1_to_R2(R, R_tmp);

    //     point_t R_i;
    //     memcpy(R_i, sig[i].R, sizeof(point_t));
    //     point_setup(R_i, R1);

    //     eccadd(R_tmp, R1);
    //     eccnorm(R1, Rr);
    // }

    // ecc_mul_fixed((digit_t*) r_A, R_mul);

    // memcpy(RA, R_mul, 64);
    // print_hex_m("MAIN ECC", RA, 64);
    // memcpy(Rt, Rr, 64);
    // print_hex_m("MAIN add", Rt, 64);
    // printf("\n[%d] [2-%d]\n", n, sizeof(point_t));