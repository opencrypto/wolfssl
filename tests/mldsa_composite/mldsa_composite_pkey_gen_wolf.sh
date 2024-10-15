#!/bin/bash

OUTDIR=artifacts
mkdir -p $OUTDIR

# Level 1
DRAFT_3_ALGOS_1="mldsa44_pss2048 mldsa44_rsa2048 mldsa44_p256 mldsa44_ed25519 mldsa44_bp256"

# Level 3
DRAFT_2_ALGOS_3="mldsa65_pss3072 mldsa65_rsa3072 mldsa65_p256 mldsa65_bp256 mldsa65_ed25519"
# DRAFT_3_ALGOS_3="mldsa65_pss3072 mldsa65_rsa3072 mldsa65_pss4096 mldsa65_rsa4096 mldsa65_p384 mldsa65_bp256 mldsa65_ed25519"

# Level 5
DRAFT_3_ALGOS_5="mldsa87_p384 mldsa87_bp384 mldsa87_ed448"

ALGOS="$DRAFT_3_ALGOS_1 $DRAFT_2_ALGOS_3 $DRAFT_3_ALGOS_5"

for algo in $ALGOS; do
    echo "Generating key for $algo"
    openssl genpkey -algorithm $algo -out $OUTDIR/$algo.key
    openssl req -new -key $OUTDIR/$algo.key -out $OUTDIR/$algo.csr -subj "/CN=$algo"
done

exit 0