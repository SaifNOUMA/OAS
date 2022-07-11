#!/bin/sh

l2=256

g++ -c -O3 -fwrapv -fomit-frame-pointer -march=native -mavx2 -D _AMD64_ -D __LINUX__ -D _AVX_ -D _AVX2_ -D _ASM_  -D USE_ENDO   tests/FOPAS_audit.c -lssl -lcrypto
g++ -o FOPAS_audit FOPAS_audit.o eccp2.o eccp2_no_endo.o eccp2_core.o fp2_1271_AVX2.o crypto_util.o schnorrq.o hash_to_curve.o kex.o sha512.o random.o  test_extras.o  -lssl -lcrypto

for l1 in {11..21}
do
    echo "Processing L1 : " $l1 "..."
    ./FOPAS_audit $l1 $l2 > logs/depth_$l1/audit_$l1.log
done
