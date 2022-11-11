#include "stdio.h"
#include "../sender/dns.h"
#include "sys/socket.h"
#include "arpa/inet.h"
#include "string.h"
#include "stdlib.h"

#define PORT 53
/*
dynamicky cist chunky
zahod packety co nejsou z example.com / prijmi jen z example.com
vytvor slozkovou strukturu 
vytvor soubor
napln soubor 
poslouchej dal pro dalsi soubor
*/
int hexchr2bin(const char hex, char *out)
{
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	} else {
		return 0;
	}

	return 1;
}

size_t hexs2bin(const char *hex, unsigned char **out)
{
	size_t len;
	char   b1;
	char   b2;
	size_t i;

	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	*out = malloc(len);
	memset(*out, 'A', len);
	for (i=0; i<len; i++) {
		if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
			return 0;
		}
		(*out)[i] = (b1 << 4) | b2;
	}
	return len;
}

int main()
{
    int fd;
    char receivedData[1000];
    // TODO memset

    struct sockaddr_in server;
    struct sockaddr_in client;
    socklen_t length;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        printf("socket() failed");

    if (bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1)
        printf("bind() failed");

    length = sizeof(client);

    char *receivedDataPointer = receivedData;
    receivedDataPointer += sizeof(struct dnsHeader);

    int n;
    while ((n = recvfrom(fd, receivedData, 1000, 0, (struct sockaddr *)&client, &length)) >= 0)
    {
        printf("data received\n");
		
		int dataLen = (int)receivedDataPointer[0];
		char* truncatedData = malloc(strlen(receivedDataPointer));
		truncatedData = strncpy(truncatedData, &receivedDataPointer[1], dataLen);

		unsigned char* decoded;
		hexs2bin(truncatedData, &decoded);
        printf("%s\n", truncatedData);
        printf("%s\n", decoded);
		
        printf("\n");
    }

    return 1;
}