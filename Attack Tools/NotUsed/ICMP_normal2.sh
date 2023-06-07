#!/bin/bash

# Simulate normal traffic
while true;
do
    packets=$(shuf -i 1-20 -n 1)
    bytes=$(shuf -i 64-128 -n 1)
    delay=$(shuf -i 1-5 -n 1)
    sudo hping3 -c $packets -d $bytes -s 80 -k 192.168.29.128
    sleep $delay
done