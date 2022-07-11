#!/bin/sh

l2=256
make clean ; make ARCH=x64
mkdir -p logs
mkdir -p data
# rm -rf data/depth_*
# rm -rf logs/depth_*

for l1 in {13..20}
do
    mkdir -p logs/depth_$l1
    mkdir -p data/depth_$l1
    mkdir -p data/depth_$l1/pk


    echo "Processing L1=" $l1 " ..."
    ./SOPAS $l1 $l2 > logs/depth_$l1/fopas_$l1.log

    echo "Processing Auditing for L1=" $l1 " ..."
    ./SOPAS_audit $l1 $l2 > logs/depth_$l1/audit_$l1.log
done
