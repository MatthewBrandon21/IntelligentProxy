#!/bin/bash

#Simulate Normal Traffic
while true; do
	packet=$(shuf -i 1-20 -n 1)
	bytes=$(shuf -i 64-200 -n 1)
	pause=$(shuf -i 1-5 -n 1)
	sudo hping3 -c $packet -d $bytes --icmp 192.168.29.128
	sleep $pause
done
	