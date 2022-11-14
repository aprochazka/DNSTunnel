CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra

all: sender receiver
    
sender: sender/dns_sender.c
	$(CC) $(CFLAGS) sender/dns_sender.c -o sender/dns_sender sender/dns_sender_events.c -L. sender/dns_sender_events.h

receiver: receiver/dns_receiver.c
	$(CC) $(CFLAGS) receiver/dns_receiver.c -o receiver/dns_receiver receiver/dns_receiver_events.c -L. receiver/dns_receiver_events.h

clean:
	rm sender/dns_sender receiver/dns_receiver
