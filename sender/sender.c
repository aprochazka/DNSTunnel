#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "dns.h"
#include "arpa/inet.h"
#include "sys/socket.h"

/*
TODO:
volani funkci z knihoven
argumenty
otevre soubor
posle se nazev a cestu
posle se content - chunksize
poslochat odpovedi (jen svoje) a kdyztak poslat znova stejnej chunk
stdin pokun neni filepath
*/

// update like in https://www.w3schools.in/c-programming/examples/reverse-a-string-in-c
unsigned char *strrev(unsigned char *str, int strSize)
{
    unsigned char *p1, *p2;

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

void transformBaseHost(unsigned char *src, unsigned char **dst, int dataLen)
{
    uint16_t srcLen = dataLen;
    unsigned char transformed[MAX_DATA_SIZE] = {0};
    int transformedIndex = 0;
    int charCount = 0;

    for (int i = srcLen - 1; i >= 0; i--)
    {
        if (src[i] == '.')
        {
            transformed[transformedIndex] = (unsigned char)charCount;
            charCount = 0;
        }
        else
        {
            transformed[transformedIndex] = src[i];
            charCount++;
        }
        transformedIndex++;
    };

    transformed[transformedIndex] = (unsigned char)charCount;

    memcpy(*dst, transformed, transformedIndex + 1);
    strrev(*dst, transformedIndex + 1);
};

int encode(unsigned char *src, unsigned char **dst, int dataLen)
{
    size_t i;
    uint16_t srcLen = dataLen;
    unsigned char *tmpDst = malloc(srcLen * 2 + 1);
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
    (*header)->id = htons(idx); // TODO change to random id

    /*
    (*header)->qr = 0;
    (*header)->opcode = 0; // 0 for standart querry
    (*header)->aa = 0;
    (*header)->tc = 0;
    (*header)->rd = 1;
    (*header)->ra = 0;
    (*header)->z = 0;
    (*header)->rcode = 0;
    */

    (*header)->flags = htons(0b0000000100000000);
    (*header)->qdcount = htons(1);
    (*header)->ancount = 0;
    (*header)->nscount = 0;
    (*header)->arcount = 0;
}

int chunkEncodedData(unsigned char *src, unsigned char **dst, int srcLen)
{
    int srcIndex = 0;
    int currentIndex = 0;
    unsigned char *chunkedBuffer = malloc(MAX_DATA_SIZE * sizeof(unsigned char));
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

int fillPacketData(unsigned char *host, unsigned char *rawData, unsigned char **dstPointer, int dataLen)
{
    unsigned char *tmpData = malloc(MAX_DATA_SIZE * sizeof(unsigned char) * 2);
    unsigned char *encoded = malloc(MAX_DATA_SIZE * sizeof(unsigned char) * 2);
    unsigned char *encodedFormatted = malloc(MAX_DATA_SIZE * sizeof(unsigned char) * 2);

    int encodedSize = encode(rawData, &encoded, dataLen);

    int chunkedSize = chunkEncodedData(encoded, &encodedFormatted, encodedSize);

    memcpy(tmpData, encodedFormatted, chunkedSize);

    memcpy(&tmpData[chunkedSize], host, strlen(host));

    int completeDataSize = chunkedSize + strlen(host);
    transformBaseHost(tmpData, &(*dstPointer), completeDataSize);
    return completeDataSize + 2; //+2 first and last number byte
}

void packetFromData(unsigned char *host, unsigned char *data, unsigned char **dstPacket, uint16_t idx, int dataLen)
{
    struct dnsHeader *header = (struct dnsHeader *)*dstPacket;
    fillHeader(&header, idx);

    *dstPacket += sizeof(struct dnsHeader);

    unsigned char QNameData[256]; // packet should have maximally 512 Bytes
    unsigned char *QNamePointer = QNameData;
    memset(QNamePointer, 0, sizeof(QNameData));
    int QNameLen = fillPacketData(host, data, &QNamePointer, dataLen);

    memcpy(*dstPacket, QNamePointer, QNameLen);

    *dstPacket += (QNameLen * sizeof(unsigned char));

    struct dnsQuestion *question = (struct dnsQuestion *)*dstPacket;

    question->QType = htons(1);
    question->QClass = htons(1);

    *dstPacket += sizeof(struct dnsQuestion);
}

int main()
{
    // SIMULATE ARGUMENTS
    unsigned char *dummyFileName = "./video.mp4";
    unsigned char *srcDummyData = "example.com";

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

    int maxQNameSize = (int)(MAX_DATA_SIZE - strlen(srcDummyData) - 5) / 2;
    unsigned char *rawDataToSend = malloc((maxQNameSize + 1) * sizeof(unsigned char));

    int eof = 0;
    uint16_t packetCounter = 2;
    FILE *fp = fopen(dummyFileName, "r");

    // TODO TO FUNCTION
    unsigned char namePacket[514]; // packet should have maximally 512 Bytes
    unsigned char *namePacketPointer = namePacket;

    memset(namePacketPointer, 0, sizeof(namePacket));

    packetFromData(srcDummyData, dummyFileName, &namePacketPointer, NAME_PACKET_ID, strlen(dummyFileName));
    size_t packetSize = namePacketPointer - namePacket;

    unsigned char response[1024];
    int num_received;
    socklen_t socklen = sizeof(struct sockaddr_in);

    sendto(sockfd, namePacket, packetSize,
           MSG_CONFIRM, (const struct sockaddr *)&servaddr,
           sizeof(servaddr));
    // END TODO

    while (!eof)
    {

        num_received = recvfrom(sockfd, response, sizeof(response), MSG_WAITALL,
                                (struct sockaddr *)&servaddr, &socklen);

        unsigned char packet[514]; // packet should have maximally 512 Bytes
        unsigned char *packetPointer = packet;

        memset(packetPointer, 0, sizeof(packet));
        memset(rawDataToSend, 0, maxQNameSize + 1);
        int bytesRead = fread(rawDataToSend, 1, maxQNameSize, fp);
        if (bytesRead <= 0)
            break;
        packetFromData(srcDummyData, rawDataToSend, &packetPointer, packetCounter, bytesRead);

        packetSize = packetPointer - packet;

        sendto(sockfd, packet, packetSize,
               MSG_CONFIRM, (const struct sockaddr *)&servaddr,
               sizeof(servaddr));
        packetCounter++;
        printf("%s\n", rawDataToSend);
    }
    fclose(fp);

    // TODO TO FUNCTION SENDENDPACKET
    unsigned char endPacket[514]; // packet should have maximally 512 Bytes
    unsigned char *endPacketPointer = endPacket;
    unsigned char *dummyEndCall = "neplecha ukoncena";
    memset(endPacketPointer, 0, sizeof(endPacket));

    packetFromData(srcDummyData, dummyEndCall, &endPacketPointer, END_PACKET_ID, strlen(dummyEndCall));
    packetSize = endPacketPointer - endPacket;
    sendto(sockfd, endPacket, packetSize,
           MSG_CONFIRM, (const struct sockaddr *)&servaddr,
           sizeof(servaddr));
    // END TODO

    printf("Done sending.\n");
    return 1;
};