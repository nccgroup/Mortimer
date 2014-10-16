#!/bin/bash

# Deletes oldest file from directory if usage over specified %
# This only deletes one file per invocation, so run frequently from cron

MOUNTPOINT=/data
SPOOL=${MOUNTPOINT}/pcap/*.pcap
PERCENT=90

tmpvar=`df ${MOUNTPOINT} | tail -1 | awk '{print $5}'`
num=${tmpvar%\%}

if [ ${num} -gt ${PERCENT} ]; then
        ls -t -1 ${SPOOL} | tail -1 | xargs rm
fi

