#!/bin/bash

RUNS=2
BURSTS=(150 120 100 80 50 30) 

for BURST in ${BURSTS[@]}
do
    for i in $(seq 1 1 "$RUNS")
    do
        echo "running benchmark with burst $BURST (run : $i)"
        if fab remote --burst $BURST \
            | tee /dev/tty \
            | grep -i "error\|exception\|traceback"
        then
            echo "Failed to complete remote benchmark"
            fab kill
            exit 2
        fi
    fab kill
    sleep 30
    echo "run $i complete"
    done
done