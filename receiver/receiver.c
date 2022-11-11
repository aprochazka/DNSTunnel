#include "stdio.h"
#include "../sender/dns.h"
#include "sys/socket.h"
#include "arpa/inet.h"
#include "string.h"

#define PORT 53

int main(int argc, char *argv[])
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
        printf("%s\n", receivedData);
        printf("%s\n", receivedDataPointer);
        printf("%ld\n", strlen(receivedDataPointer));
        printf("\n");
    }

    return 1;
}