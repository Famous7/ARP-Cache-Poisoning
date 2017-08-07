all: arp_spoffing

arp_spoffing: arp_spoffing.o
	gcc -o arp_spoffing arp_spoffing.o -l pcap -l pthread

arp_spoffing.o: arp_spoffing.c
	gcc -o arp_spoffing.o -c arp_spoffing.c

clean:
	rm arp_spoffing.o arp_spoffing
