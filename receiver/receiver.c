#include "stdio.h"
#include "../sender/dns.h"
#include "sys/socket.h"
#include "arpa/inet.h"
#include "string.h"
#include "stdlib.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "arpa/inet.h"
#include "sys/socket.h"

////////
///////
//////	ZKOPIROVANY FONKCE ZE SENDERU, PAK PREDELAT DO EXTERNIHO SOUBORU
//////
///////

void prepareResponse(char *srcPacket, short id)
{
	struct dnsHeader *header = (struct dnsHeader *)(srcPacket - sizeof(struct dnsHeader));
	header->id = htons(id);
	header->flags = htons(0b1000000100000101);
	header->qdcount = htons(1);
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;
}

////////
///////
//////	ZKOPIROVANY FONKCE ZE SENDERU, PAK PREDELAT DO EXTERNIHO SOUBORU
//////
///////

/*
vytvor slozkovou strukturu
poslouchej dal pro dalsi soubor
predelat dekodovani
*/
int hexchr2bin(const char hex, char *out)
{
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9')
	{
		*out = hex - '0';
	}
	else if (hex >= 'A' && hex <= 'F')
	{
		*out = hex - 'A' + 10;
	}
	else if (hex >= 'a' && hex <= 'f')
	{
		*out = hex - 'a' + 10;
	}
	else
	{
		return 0;
	}

	return 1;
}

size_t hexs2bin(const char *hex, unsigned char **out)
{
	size_t len;
	char b1;
	char b2;
	size_t i;

	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	*out = malloc(len);
	// memset(*out, 'A', len);
	for (i = 0; i < len; i++)
	{
		if (!hexchr2bin(hex[i * 2], &b1) || !hexchr2bin(hex[i * 2 + 1], &b2))
		{
			return 0;
		}
		(*out)[i] = (b1 << 4) | b2;
	}
	return len;
}

// COPYPASTEEE
//  update like in https://www.w3schools.in/c-programming/examples/reverse-a-string-in-c
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

// MOVE TO LIBRARY -- COPY PASTE FROM SENDER
void transformBaseHost(char *src, char **dst)
{
	uint16_t srcLen = strlen(src);
	char transformed[MAX_DATA_SIZE] = {0};
	int transformedIndex = 0;
	int charCount = 0;

	for (int i = srcLen - 1; i >= 0; i--)
	{
		if (src[i] == '.')
		{
			transformed[transformedIndex] = (char)charCount;
			charCount = 0;
		}
		else
		{
			transformed[transformedIndex] = src[i];
			charCount++;
		}
		transformedIndex++;
	};

	transformed[transformedIndex] = (char)charCount;

	strcpy(*dst, transformed);
	strrev(*dst);
};

int isPacketStartEnd(char *packet)
{
	short *packetIdPointer = (short *)(packet - sizeof(struct dnsHeader) - 2);

	int firstByte = htons(packetIdPointer[0]);
	int secondByte = htons(packetIdPointer[1]);

	if (firstByte == 0 && secondByte == 1)
		return 1;
	if (firstByte == 0 && secondByte == 0)
		return -1;
	return 0;
}

int recognizePacket(char *packet, char *baseHost)
{
	char *transformedBaseHost = malloc((strlen(baseHost) + 2) * sizeof(char));
	char *hostFromPacket = malloc((strlen(baseHost) + 2) * sizeof(char));
	transformBaseHost(baseHost, &transformedBaseHost);
	strncpy(hostFromPacket, &packet[strlen(packet) - strlen(transformedBaseHost)], strlen(transformedBaseHost));
	return strcmp(transformedBaseHost, hostFromPacket);
}

int getChunk(char *src, char **dst, int chunkSizeIndex)
{
	int dataLen = (int)src[chunkSizeIndex];
	char *truncatedData = malloc(dataLen + 1);
	truncatedData = memcpy(truncatedData, &src[chunkSizeIndex + 1], dataLen);
	memcpy(*dst, truncatedData, chunkSizeIndex);
	return chunkSizeIndex + dataLen + 1;
}

int getChunks(char *src, char *dst)
{
	int chunkSizeIndex = 0;
	int dstIndex = 0;
	while (src[chunkSizeIndex] != '\0')
	{
		memcpy(&dst[dstIndex], &src[chunkSizeIndex + 1], src[chunkSizeIndex]);
		dstIndex += (int)src[chunkSizeIndex];
		chunkSizeIndex += (int)src[chunkSizeIndex] + 1;
		if ((int)src[chunkSizeIndex] == 0)
			break;
	}
	return dstIndex;
}

int main()
{
	// argument simulation
	char *baseHost = BASE_HOST;

	int fd;
	char receivedData[1000];

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

	int n;
	while ((n = recvfrom(fd, receivedData, 1000, 0, (struct sockaddr *)&client, &length)) >= 0)
	{
		char *receivedDataPointer = receivedData;
		receivedDataPointer += sizeof(struct dnsHeader);
		uint64_t packetIndex = 1;
		if (recognizePacket(receivedDataPointer, baseHost) != 0)
			continue;
		if (isPacketStartEnd(receivedDataPointer) != 1)
			continue;

		unsigned char *fileName;
		char *nameEncodedBuffer = malloc(MAX_DATA_SIZE + 2);
		getChunks(receivedDataPointer, nameEncodedBuffer);
		hexs2bin(nameEncodedBuffer, &fileName);

		FILE *fp = fopen((char *)fileName, "w+");
		if (fp == NULL)
		{
			printf("failed to open file: %s\n", (char *)fileName);
			continue;
		}

		prepareResponse(receivedDataPointer, packetIndex);
		packetIndex++;
		sendto(fd, receivedData, n, 0, (struct sockaddr *)&client,
			   sizeof(client));

		while ((n = recvfrom(fd, receivedData, 1000, 0, (struct sockaddr *)&client, &length)) >= 0)
		{
			if (isPacketStartEnd(receivedDataPointer) == -1)
				break;
			char *encodedBuffer = malloc(MAX_DATA_SIZE + 2);
			int dataLen = getChunks(receivedDataPointer, encodedBuffer);
			unsigned char *decoded;
			hexs2bin(encodedBuffer, &decoded);
			fwrite(decoded, 1, dataLen / 2 - 5, fp);

			prepareResponse(receivedDataPointer, packetIndex);
			packetIndex++;
			sendto(fd, receivedData, n, 0, (struct sockaddr *)&client,
				   sizeof(client));
		}

		fclose(fp);
	}

	return 1;
}