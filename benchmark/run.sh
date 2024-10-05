#!/bin/bash

RUNS=1
BURSTS=(32000 64000 128000 192000 256000 512000 768000)

for BURST in ${BURSTS[@]}
do
    for i in $(seq 1 1 "$RUNS")
    do
        echo "running benchmark with burst $BURST (run : $i)"
        if fab remote --consensus-only --header-size $BURST \
            | tee /dev/tty \
            | grep -i "error\|exception\|traceback"
        then
            echo "Failed to complete remote benchmark"
            fab kill
            exit 2
        fi
    fab kill
    sleep 20
    echo "run $i complete"
    done
done