#!/bin/sh

l1=$1
l2=256
make clean ; make ARCH=x64
mkdir -p logs
mkdir -p data
# rm -rf data/depth_*
# rm -rf logs/depth_*

mkdir -p logs/depth_$l1
mkdir -p data/depth_$l1
mkdir -p data/depth_$l1/pk

echo "Processing L1 : " $l1
./SOCOSA
