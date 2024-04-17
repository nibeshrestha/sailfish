#!/bin/bash

RUNS=3
BURSTS=(110 120 130) 

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
    sleep 20
    echo "run $i complete"
    done
    fab stop
    sleep 60
    fab start
    sleep 60
done