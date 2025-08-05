#!/bin/bash

sudo tcpdump -i lo "udp port 9999 or udp port 2152 or sctp or port 38462 or port 38472 or port 38412 or port 2153" -w ./configs/rec.pcapng &
tcpdump_pid=$!

./nr-softmodem -O configs/gnb-du.sa.band78.106prb.usrpb200.conf --rfsim --sa -E --log_config.global_log_options level,time --T_stdout 2 &
gnb_pid=$!


cd /oai/common/utils/T/tracer
make 

sleep 1

./macpdu2wireshark -d ../T_messages.txt -live