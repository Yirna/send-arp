all: send-arp

send-arp: send-arp.c
	gcc  -o send-arp send-arp.c -lpcap


