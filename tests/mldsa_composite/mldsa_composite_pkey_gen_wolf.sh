#!/bin/bash

OUTDIR=artifacts
mkdir -p $OUTDIR

TRADITIONAL_ALGOS="rsa2048 rsapss2048 rsa3072 rsapss3072 rsa4096 rsapss4096 p256 p384 p521 bp256 bp384 bp512 ed25519 ed448"

for algo in $TRADITIONAL_ALGOS; do
    if [ "$algo" == "rsa2048" -o "$algo" == "rsapss2048" ]; then
        OPT="-bits 2048"
    elif [ "$algo" == "rsa3072" -o "$algo" == "rsapss3072" ]; then
        OPT="-bits 3072"
    elif [ "$algo" == "rsa4096" -o "$algo" == "rsapss4096" ]; then
        OPT="-bits 4096"
    fi
    echo -n "Generating key for $algo ... "
    examples/pktool/.libs/pktool genpkey -algorithm $algo $OPT -out $OUTDIR/$algo.key && echo "done" || ( echo "failed" && exit 1 )
    echo -n "Generating csr for $algo ... "
    examples/pktool/.libs/pktool genreq -key $OUTDIR/$algo.key -out $OUTDIR/$algo.req && echo "done" || ( echo "failed" && exit 1 )
done

# Level 1
DRAFT_3_ALGOS_1="mldsa44-rsapss2048 mldsa44-rsa2048 mldsa44-p256 mldsa44-ed25519"
DRAFT_3_ALGOS_3="mldsa65-rsapss3072 mldsa65-rsa3072 mldsa65-rsapss4096 mldsa65-rsa4096 mldsa65-p256 mldsa65-bp256 mldsa65-ed25519"
DRAFT_3_ALGOS_5="mldsa87-p384 mldsa87-bp384 mldsa87-ed448"

# # Level 3
# DRAFT_2_ALGOS_3="mldsa65_pss3072 mldsa65_rsa3072 mldsa65_p256 mldsa65_bp256 mldsa65_ed25519"
# # DRAFT_3_ALGOS_3="mldsa65_pss3072 mldsa65_rsa3072 mldsa65_pss4096 mldsa65_rsa4096 mldsa65_p384 mldsa65_bp256 mldsa65_ed25519"

# # Level 5
# # DRAFT_3_ALGOS_5="mldsa87_p384 mldsa87_bp384 mldsa87_ed448"

# # ALGOS="$DRAFT_3_ALGOS_1 $DRAFT_2_ALGOS_3 $DRAFT_3_ALGOS_5"

ALGOS="$DRAFT_3_ALGOS_1 $DRAFT_3_ALGOS_3 $DRAFT_3_ALGOS_5"

for algo in $ALGOS; do
    echo -n "Generating key for $algo ... "
    examples/pktool/.libs/pktool genpkey -algorithm $algo -out $OUTDIR/$algo.key && echo "done" || ( echo "failed" && exit 1 )
    echo -n "Generating csr for $algo ... "
    examples/pktool/.libs/pktool genreq -key $OUTDIR/$algo.key -out $OUTDIR/$algo.req && echo "done" || ( echo "failed" && exit 1 )
done

echo "All keys generated successfully"

exit 0;
