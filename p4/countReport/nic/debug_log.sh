#!/bin/bash

rm -f debug_nic.log

i=0

while true; do
	echo $'\n ${i} * 0.5 seconds\n' >> debug_nic.log
	~/network_cards/nfp-sdk-6.0.1/p4/bin/rtecli registers -r debug_counter -i 0 get >> debug_nic.log
	sleep 0.5
	((i ++))
done

