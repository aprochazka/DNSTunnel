#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "dns.h"
#include "arpa/inet.h"
#include "sys/socket.h"
#include "sender.h"
#include "dns_sender_events.h"

// update like in https://www.w3schools.in/c-programming/examples/reverse-a-string-in-c
uint8_t *strrev(uint8_t *str, int strSize)
{
    uint8_t *p1, *p2;

    if (!str || !*str)
        return str;
    for (p1 = str, p2 = str + strSize - 1; p2 > p1; ++p1, --p2)
    {
        *p1 ^= *p2;
        *p2 ^= *p1;
        *p1 ^= *p2;
    }
    return str;
}

void transformBaseHost(uint8_t *src, uint8_t **dst, int dataLen)
{
    uint16_t srcLen = dataLen;
    uint8_t transformed[MAX_DATA_SIZE] = {0};
    int transformedIndex = 0;
    int charCount = 0;

    for (int i = srcLen - 1; i >= 0; i--)
    {
        if (src[i] == '.')
        {
            transformed[transformedIndex] = (uint8_t)charCount;
            charCount = 0;
        }
        else
        {
            transformed[transformedIndex] = src[i];
            charCount++;
        }
        transformedIndex++;
    };

    transformed[transformedIndex] = (uint8_t)charCount;

    memcpy(*dst, transformed, transformedIndex + 1);
    strrev(*dst, transformedIndex + 1);
};

int encode(uint8_t *src, uint8_t **dst, int dataLen)
{
    size_t i;
    uint16_t srcLen = dataLen;
    uint8_t *tmpDst = malloc(srcLen * 2 + 1);
    for (i = 0; i < srcLen; i++)
    {
        tmpDst[i * 2] = "0123456789ABCDEF"[src[i] >> 4];
        tmpDst[i * 2 + 1] = "0123456789ABCDEF"[src[i] & 0x0F];
    }

    *dst = malloc(srcLen * 2 + 1);
    memcpy(*dst, tmpDst, dataLen * 2);
    return dataLen * 2;
}

void fillHeader(struct dnsHeader **header, uint16_t idx)
{
    (*header)->id = htons(idx);
    (*header)->flags = htons(0b0000000100000000);
    (*header)->qdcount = htons(1);
    (*header)->ancount = 0;
    (*header)->nscount = 0;
    (*header)->arcount = 0;
}

int chunkEncodedData(uint8_t *src, uint8_t **dst, int srcLen)
{
    int srcIndex = 0;
    int currentIndex = 0;
    uint8_t *chunkedBuffer = malloc(MAX_DATA_SIZE * sizeof(uint8_t));
    int chunkCounter = 0;
    while (srcIndex < srcLen - 1)
    {
        int chunkSize;
        if (srcLen - srcIndex > MAX_CHUNK_SIZE)
        {
            chunkSize = MAX_CHUNK_SIZE - 1; // ONE BYTE FOR CHUNK LENGTH
        }
        else
        {
            chunkSize = srcLen - srcIndex; // SET CHUNK SIZE FOR REMAINING DATA
        }
        memcpy(&chunkedBuffer[currentIndex], &src[srcIndex], chunkSize);

        srcIndex += chunkSize;
        currentIndex += chunkSize;
        chunkedBuffer[currentIndex] = '.';
        chunkCounter++;
        currentIndex++;
    }

    int chunkedSize = srcLen + chunkCounter;
    memcpy(*dst, chunkedBuffer, chunkedSize);
    return chunkedSize;
}

int fillPacketData(char *host, uint8_t *rawData, uint8_t **dstPointer, int dataLen, char *filePath, int chunkId)
{
    uint8_t *tmpData = malloc(MAX_DATA_SIZE * sizeof(uint8_t) * 2);
    uint8_t *encoded = malloc(MAX_DATA_SIZE * sizeof(uint8_t) * 2);
    uint8_t *encodedFormatted = malloc(MAX_DATA_SIZE * sizeof(uint8_t) * 2);

    int encodedSize = encode(rawData, &encoded, dataLen);

    int chunkedSize = chunkEncodedData(encoded, &encodedFormatted, encodedSize);

    memcpy(tmpData, encodedFormatted, chunkedSize);

    memcpy(&tmpData[chunkedSize], host, strlen(host));

    int completeDataSize = chunkedSize + strlen(host);

    dns_sender__on_chunk_encoded(filePath, chunkId, (char *)tmpData);

    transformBaseHost(tmpData, &(*dstPointer), completeDataSize);
    return completeDataSize + 2; //+2 first and last number byte
}

void getDefaultDNS(char **dst)
{
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (fp == NULL)
        return;

    int found = 0;
    char line[500];
    char *token;
    while (fgets(line, 500, fp))
    {
        token = strtok(line, " ");
        while (token != NULL)
        {
            if (strcmp(token, "nameserver") == 0)
            {
                token = strtok(NULL, " ");
                *dst = malloc((strlen(token)) * sizeof(char));
                strcpy(*dst, token);
                found = 1;
                return;
            }
            token = strtok(NULL, " ");
        }
        if (found)
            break;
    }

    return;
}

void packetFromData(char *host, uint8_t *data, uint8_t **dstPacket, uint16_t idx, int dataLen, char *filePath)
{
    struct dnsHeader *header = (struct dnsHeader *)*dstPacket;
    fillHeader(&header, idx);

    *dstPacket += sizeof(struct dnsHeader);

    uint8_t QNameData[256]; // packet should have maximally 512 Bytes
    uint8_t *QNamePointer = QNameData;
    memset(QNamePointer, 0, sizeof(QNameData));
    int QNameLen = fillPacketData(host, data, &QNamePointer, dataLen, filePath, idx);

    memcpy(*dstPacket, QNamePointer, QNameLen);

    *dstPacket += (QNameLen * sizeof(uint8_t));

    struct dnsQuestion *question = (struct dnsQuestion *)*dstPacket;

    question->QType = htons(1);
    question->QClass = htons(1);

    *dstPacket += sizeof(struct dnsQuestion);
}

void fillArguments(struct args *arguments, int argc, char *argv[])
{
    arguments->UPSTREAM_DNS_IP = NULL;
    arguments->BASE_HOST = NULL;
    arguments->DST_FILEPATH = NULL;
    arguments->SRC_FILEPATH = NULL;
    int baseArgCount = 0;
    for (int i = 0; i < argc; i++)
        for (int currArg = 1; currArg < argc; currArg++)
        {
            if (strcmp(argv[currArg], "-u") == 0)
            {
                arguments->UPSTREAM_DNS_IP = malloc(strlen(argv[currArg + 1]) * sizeof(char) + 1);
                strcpy(arguments->UPSTREAM_DNS_IP, argv[currArg + 1]);
                currArg++;
            }
            else
            {
                switch (baseArgCount)
                {
                case 0:
                    arguments->BASE_HOST = malloc(strlen(argv[currArg]) * sizeof(char) + 1);
                    strcpy(arguments->BASE_HOST, argv[currArg]);
                    break;
                case 1:
                    arguments->DST_FILEPATH = malloc(strlen(argv[currArg]) * sizeof(char) + 1);
                    strcpy(arguments->DST_FILEPATH, argv[currArg]);
                    break;
                case 2:
                    arguments->SRC_FILEPATH = malloc(strlen(argv[currArg]) * sizeof(char) + 1);
                    strcpy(arguments->SRC_FILEPATH, argv[currArg]);
                    break;
                default:
                    break;
                }
                baseArgCount++;
            }
        }
}

int main(int argc, char *argv[])
{
    struct args *arguments = malloc(sizeof(struct args));
    fillArguments(arguments, argc, argv);
    int sockfd;
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        exit(EXIT_FAILURE);
    }

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    if (arguments->UPSTREAM_DNS_IP == NULL)
    {
        char *defaultUpstream;
        getDefaultDNS(&defaultUpstream);
        servaddr.sin_addr.s_addr = inet_addr(defaultUpstream);
    }
    else
    {
        servaddr.sin_addr.s_addr = inet_addr(arguments->UPSTREAM_DNS_IP);
    }

    int maxQNameSize = (int)(MAX_DATA_SIZE - strlen(arguments->BASE_HOST) - 5) / 2;
    uint8_t *rawDataToSend = malloc((maxQNameSize + 1) * sizeof(uint8_t));

    int eof = 0;
    uint16_t packetCounter = 2;
    FILE *fp = NULL;
    if (arguments->SRC_FILEPATH != NULL)
        fp = fopen(arguments->SRC_FILEPATH, "r");

    // TODO TO FUNCTION
    uint8_t namePacket[514]; // packet should have maximally 512 Bytes
    uint8_t *namePacketPointer = namePacket;

    memset(namePacketPointer, 0, sizeof(namePacket));

    packetFromData(arguments->BASE_HOST, (uint8_t *)arguments->DST_FILEPATH, &namePacketPointer, NAME_PACKET_ID, strlen(arguments->DST_FILEPATH), arguments->DST_FILEPATH);
    size_t packetSize = namePacketPointer - namePacket;

    uint8_t response[1024];
    socklen_t socklen = sizeof(struct sockaddr_in);

    // ASSIGNMEN FUNCTION
    dns_sender__on_chunk_sent(&servaddr.sin_addr, arguments->DST_FILEPATH, NAME_PACKET_ID, packetSize);

    sendto(sockfd, namePacket, packetSize,
           MSG_CONFIRM, (const struct sockaddr *)&servaddr,
           sizeof(servaddr));
    // END TODO
    int waitInWhile = 0;
    recvfrom(sockfd, response, sizeof(response), MSG_WAITALL,
             (struct sockaddr *)&servaddr, &socklen);

    // ASSIGNMEN FUNCTION
    dns_sender__on_transfer_init(&servaddr.sin_addr);
    int fileSize = 0;
    while (!eof)
    {
        if (waitInWhile)
        {
            recvfrom(sockfd, response, sizeof(response), MSG_WAITALL,
                     (struct sockaddr *)&servaddr, &socklen);
        }
        else
        {
            waitInWhile = 1;
        }

        uint8_t packet[514]; // packet should have maximally 512 Bytes
        uint8_t *packetPointer = packet;

        memset(packetPointer, 0, sizeof(packet));
        memset(rawDataToSend, 0, maxQNameSize + 1);
        int bytesRead;
        if (fp == NULL)
        {
            bytesRead = fread(rawDataToSend, 1, maxQNameSize, stdin);
        }
        else
        {
            bytesRead = fread(rawDataToSend, 1, maxQNameSize, fp);
        }

        if (bytesRead <= 0)
            break;

        fileSize += bytesRead;

        packetFromData(arguments->BASE_HOST, rawDataToSend, &packetPointer, packetCounter, bytesRead, arguments->DST_FILEPATH);

        packetSize = packetPointer - packet;

        // ASSIGNMEN FUNCTION
        dns_sender__on_chunk_sent(&servaddr.sin_addr, arguments->DST_FILEPATH, packetCounter, packetSize);

        sendto(sockfd, packet, packetSize,
               MSG_CONFIRM, (const struct sockaddr *)&servaddr,
               sizeof(servaddr));
        packetCounter++;
    }
    if (fp != NULL)
        fclose(fp);

    // TODO TO FUNCTION SENDENDPACKET
    uint8_t endPacket[514]; // packet should have maximally 512 Bytes
    uint8_t *endPacketPointer = endPacket;
    char *endTransfer = "END OF TRANSFER";
    memset(endPacketPointer, 0, sizeof(endPacket));

    packetFromData(arguments->BASE_HOST, (uint8_t *)endTransfer, &endPacketPointer, END_PACKET_ID, strlen(endTransfer), arguments->DST_FILEPATH);
    packetSize = endPacketPointer - endPacket;

    // ASSIGNMEN FUNCTION
    dns_sender__on_chunk_sent(&servaddr.sin_addr, arguments->DST_FILEPATH, END_PACKET_ID, packetSize);

    sendto(sockfd, endPacket, packetSize,
           MSG_CONFIRM, (const struct sockaddr *)&servaddr,
           sizeof(servaddr));
    // END TODO

    // ASSIGNMEN FUNCTION
    dns_sender__on_transfer_completed(arguments->DST_FILEPATH, fileSize);
    return 1;
};