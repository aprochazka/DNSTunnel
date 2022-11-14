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
#include "receiver.h"
#include "sys/stat.h"
#include "errno.h"
#include "dns_receiver_events.h"

#define PATH_MAX 255
#define DATA_CHUNK_ID 2

int mkdir_p(const char *pathname)
{
	char *tok = NULL;
	char path[PATH_MAX + 1] = {0};
	char tmp[PATH_MAX + 1] = {0};
	struct stat st = {0};
	char *pathNameCropped = malloc(strlen(pathname) + 1);
	strcpy(pathNameCropped, pathname);

	/* remove filename from path */
	int i = strlen(pathNameCropped) - 1;
	for (; pathNameCropped[i] != '/' && i > 0; i--)
		pathNameCropped[i] = (char)0;
	pathNameCropped[i] = (char)0;

	/* pathname already exists and is a directory */
	if (stat(pathNameCropped, &st) == 0 && S_ISDIR(st.st_mode))
		return 0;

	/* doesn't need parent directories created */
	if (mkdir(pathNameCropped, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0)
		return 0;

	/* prepend initial / if needed */
	if (pathNameCropped[0] == '/')
		tmp[0] = '/';

	/* prepend initial ./ if needed */
	if (pathNameCropped[0] == '.' && pathNameCropped[1] == '/')
	{
		tmp[0] = '.';
		tmp[1] = '/';
	}

	/* make a copy of pathname and start tokenizing it */
	strncpy(path, pathNameCropped, PATH_MAX);
	tok = strtok(path, "/");

	/* keep going until there are no tokens left */
	while (tok)
	{
		/* append the next token to the path */
		strcat(tmp, tok);

		/* create the directory and keep going unless mkdir fails and
		 * errno doesn't indicate that the path already exists */
		errno = 0;

		mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO | S_IROTH | S_IXOTH);

		/* append a / to the path for the next token and get it */
		strcat(tmp, "/");
		tok = strtok(NULL, "/");
	}

	/* success */
	return 0;
}

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

/*
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
	hostFromPacket[strlen(transformedBaseHost)] = (char)0;
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

int parseArguments(struct args *arguments, int argc, char *argv[])
{
	arguments->BASE_HOST = NULL;
	arguments->DST_FILEPATH = NULL;
	if (argc != 3)
	{
		return 0;
	}
	arguments->BASE_HOST = malloc(strlen(argv[1]) * sizeof(char) + 1);
	strcpy(arguments->BASE_HOST, argv[1]);
	arguments->DST_FILEPATH = malloc(strlen(argv[2]) * sizeof(char) + 1);
	strcpy(arguments->DST_FILEPATH, argv[2]);
	return 1;
}

int baseHostIndex(char *src, char *baseHost)
{
	int i = strlen(src);
	int k = strlen(baseHost);
	while (i > 0)
	{
		i--;
		k--;
		if (src[i] != baseHost[k])
		{
			if (baseHost[k] == '.')
			{
				k--;
				continue;
			}
			return i;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct args *arguments = malloc(sizeof(struct args));
	if (parseArguments(arguments, argc, argv) != 1)
	{
		printf("wrong number of arguments\n");
		return 1;
	}

	int fd;

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

	char receivedData[1000];
	char *receivedDataPointer = receivedData;
	receivedDataPointer += sizeof(struct dnsHeader);
	int n;

	while ((n = recvfrom(fd, receivedData, 1000, MSG_WAITALL, (struct sockaddr *)&client, &length)) >= 0)
	{

		uint64_t packetIndex = 1;
		if (recognizePacket(receivedDataPointer, arguments->BASE_HOST) != 0)
		{
			continue;
		}
		if (isPacketStartEnd(receivedDataPointer) != 1)
		{
			continue;
		}

		char *fileName = malloc(MAX_DATA_SIZE);
		char *nameEncodedBuffer = malloc(MAX_DATA_SIZE + 2);
		memset(fileName, 0, MAX_DATA_SIZE);
		memset(nameEncodedBuffer, 0, MAX_DATA_SIZE + 2);
		int fileNameLen = getChunks(receivedDataPointer, nameEncodedBuffer);
		printf("%s\n", nameEncodedBuffer);
		hexs2bin(nameEncodedBuffer, (unsigned char **)&fileName);
		fileName[(baseHostIndex(nameEncodedBuffer, arguments->BASE_HOST) + 1) / 2] = '\0';
		printf("%d\n", fileNameLen);
		printf("%s\n", fileName);
		printf("%d\n", baseHostIndex(nameEncodedBuffer, arguments->BASE_HOST));

		//
		// OPEN FILE
		//
		char *pathToFile = malloc(strlen(arguments->DST_FILEPATH) + fileNameLen + 4);
		strcpy(pathToFile, arguments->DST_FILEPATH);
		strcat(pathToFile, "/");
		strcat(pathToFile, (char *)fileName);
		printf("1\n");

		mkdir_p(pathToFile);
		FILE *fp = fopen((char *)pathToFile, "w+");
		if (fp == NULL)
		{
			printf("failed to open file: %s\n", (char *)pathToFile);
			continue;
		}
		// OPEN FILE END

		dns_receiver__on_transfer_init(&client.sin_addr);

		prepareResponse(receivedDataPointer, packetIndex);
		packetIndex++;
		sendto(fd, receivedData, n, 0, (struct sockaddr *)&client,
			   sizeof(client));

		int chunkId = DATA_CHUNK_ID;
		int fileSize = 0;
		memset(receivedData, (char)0, 1000);
		while ((n = recvfrom(fd, receivedData, 1000, MSG_WAITALL, (struct sockaddr *)&client, &length)) >= 0)
		{
			if (recognizePacket(receivedDataPointer, arguments->BASE_HOST) != 0)
			{
				continue;
			}

			if (isPacketStartEnd(receivedDataPointer) == -1)
				break;

			// ASSIGNMENT FUNCTION
			dns_receiver__on_chunk_received(&client.sin_addr, pathToFile, chunkId, strlen(receivedDataPointer));

			char *encodedBuffer = malloc(MAX_DATA_SIZE + 2);
			int dataLen = getChunks(receivedDataPointer, encodedBuffer);

			// ASSIGNMENT FUNCTION
			dns_receiver__on_query_parsed(pathToFile, encodedBuffer);

			unsigned char *decoded;
			hexs2bin(encodedBuffer, &decoded);

			int chunkSize = dataLen / 2 - 5;

			chunkId++;

			fwrite(decoded, 1, chunkSize, fp);
			fileSize += chunkSize;
			prepareResponse(receivedDataPointer, packetIndex);
			packetIndex++;
			sendto(fd, receivedData, n, 0, (struct sockaddr *)&client,
				   sizeof(client));
			memset(receivedData, (char)0, 1000);
		}

		fclose(fp);
		dns_receiver__on_transfer_completed(pathToFile, fileSize);
		memset(receivedData, (char)0, 1000);
	}

	return 1;
}