#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "dns.h"
#include "arpa/inet.h"
#include "sys/socket.h"

#define IP_ADDR "172.31.80.1"
#define PORT 53
#define BASE_HOST "example.com"
#define SRC_FILE "./data.txt"
#define DST_FILE "data.txt"
#define MAX_PACKET_SIZE 255

// update like in https://www.w3schools.in/c-programming/examples/reverse-a-string-in-c
char *strrev(char *str)
{
    char *p1, *p2;

    if (!str || !*str)
        return str;
    for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2)
    {
        *p1 ^= *p2;
        *p2 ^= *p1;
        *p1 ^= *p2;
    }
    return str;
}

void transformBaseHost(char *src, char **dst)
{
    uint16_t srcLen = strlen(src);
    char transformed[MAX_PACKET_SIZE] = {0};
    int transformedIndex = 0;
    int charCount = 0;

    transformed[transformedIndex] = '0';
    transformedIndex++;

    for (int i = srcLen - 1; i >= 0; i--)
    {
        if (src[i] == '.')
        {
            transformed[transformedIndex] = charCount + '0';
            charCount = 0;
        }
        else
        {
            transformed[transformedIndex] = src[i];
            charCount++;
        }
        transformedIndex++;
    };

    transformed[transformedIndex] = charCount + '0';

    *dst = malloc(strlen(transformed) + 1 * sizeof(char));
    strcpy(*dst, transformed);
    strrev(*dst);
};

void encode(char *src, char **dst)
{

    size_t i;
    uint16_t srcLen = strlen(src);
    char *tmpDst = malloc(srcLen * 2 + 1);
    for (i = 0; i < srcLen; i++)
    {
        tmpDst[i * 2] = "0123456789ABCDEF"[src[i] >> 4];
        tmpDst[i * 2 + 1] = "0123456789ABCDEF"[src[i] & 0x0F];
    }
    tmpDst[srcLen * 2] = '\0';

    *dst = malloc(srcLen * 2 + 1);
    strcpy(*dst, tmpDst);
}

int main(int argc, char *argv[])
{

    char *host = BASE_HOST;
    char *dst;

    encode(host, &dst);
    printf("%s", dst);

    unsigned char packet[564]; // packet should have maximally 512 Bytes
    unsigned char *packetPointer = packet;
    memset(packetPointer, 0, sizeof(packet));

    // FILL HEADER
    struct dnsHeader *header = (struct dnsHeader *)packetPointer; // MOZNA CHYBI VYPRCANT
    header->id = (uint16_t)333;                                   // TODO change to random id
    header->qr = 0;
    header->opcode = 0; // 0 for standart querry
    header->aa = 0;
    header->tc = 0;
    header->rd = 1;
    header->ra = 0;
    header->z = 0;
    header->rcode = 0;
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    // FILL HEADER END

    packetPointer += sizeof(struct dnsHeader); // move pointer

    // MANUALLY INSERT QNAME
    char *baseHost = BASE_HOST;
    char *dummyData = "3www3abc7example3com0";
    // strcat(dummyData, baseHost);

    memcpy(packetPointer, dummyData, strlen(dummyData));

    packetPointer += strlen(dummyData);

    struct dnsQuestion *question = (struct dnsQuestion *)packetPointer;

    question->QType = htons(1);
    question->QType = htons(1);

    packetPointer += sizeof(struct dnsQuestion);

    size_t packetSize = packetPointer - packet;

    int sockfd;
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    sendto(sockfd, packet, packetSize,
           MSG_CONFIRM, (const struct sockaddr *)&servaddr,
           sizeof(servaddr));
    printf("message sent.\n");

    printf("%s", packet);

    return 1;
};