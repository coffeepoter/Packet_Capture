#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

// TCP 패킷의 세부 정보를 출력하는 함수
void print_tcp_packet(const u_char *packet, FILE *log_file)
{
    // IP 헤더를 패킷에서 추출
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned short ip_header_len = ip->iph_ihl * 4; // IP 헤더 길이 계산

    // TCP 헤더를 패킷에서 추출
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // 페이로드 시작 위치와 길이 계산
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + (tcp->tcp_offx2 >> 4) * 4;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - (tcp->tcp_offx2 >> 4) * 4;

    // 로그 파일에 TCP 패킷 정보 출력
    fprintf(log_file, "\nTCP Packet\n");
    fprintf(log_file, "   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    fprintf(log_file, "   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    fprintf(log_file, "   Source Port: %u\n", ntohs(tcp->tcp_sport));
    fprintf(log_file, "   Destination Port: %u\n", ntohs(tcp->tcp_dport));
    fprintf(log_file, "   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    fprintf(log_file, "   Payload (%d bytes):\n", payload_len);

    // 페이로드 내용을 출력
    for (int i = 0; i < payload_len; i++)
    {
        fprintf(log_file, "%02x ", payload[i]);
        // 16바이트마다 줄 바꿈
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    fprintf(log_file, "\n");

    // 콘솔에도 TCP 패킷 정보 출력
    printf("\nTCP Packet\n");
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("   Source Port: %u\n", ntohs(tcp->tcp_sport));
    printf("   Destination Port: %u\n", ntohs(tcp->tcp_dport));
    printf("   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    printf("   Payload (%d bytes):\n", payload_len);

    // 페이로드 내용을 콘솔에 출력
    for (int i = 0; i < payload_len; i++)
    {
        printf("%02x ", payload[i]);
        // 16바이트마다 줄 바꿈
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

// UDP 패킷의 세부 정보를 출력하는 함수
void print_udp_packet(const u_char *packet, FILE *log_file)
{
    // IP 헤더를 패킷에서 추출
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned short ip_header_len = ip->iph_ihl * 4; // IP 헤더 길이 계산

    // UDP 헤더를 패킷에서 추출
    struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // 페이로드 시작 위치와 길이 계산
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + sizeof(struct udpheader);
    int payload_len = ntohs(udp->udp_ulen) - sizeof(struct udpheader);

    // 로그 파일에 UDP 패킷 정보 출력
    fprintf(log_file, "\nUDP Packet\n");
    fprintf(log_file, "   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    fprintf(log_file, "   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    fprintf(log_file, "   Source Port: %u\n", ntohs(udp->udp_sport));
    fprintf(log_file, "   Destination Port: %u\n", ntohs(udp->udp_dport));
    fprintf(log_file, "   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    fprintf(log_file, "   Payload (%d bytes):\n", payload_len);

    // 페이로드 내용을 출력
    for (int i = 0; i < payload_len; i++)
    {
        fprintf(log_file, "%02x ", payload[i]);
        // 16바이트마다 줄 바꿈
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    fprintf(log_file, "\n");

    // 콘솔에도 UDP 패킷 정보 출력
    printf("\nUDP Packet\n");
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("   Source Port: %u\n", ntohs(udp->udp_sport));
    printf("   Destination Port: %u\n", ntohs(udp->udp_dport));
    printf("   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    printf("   Payload (%d bytes):\n", payload_len);

    // 페이로드 내용을 콘솔에 출력
    for (int i = 0; i < payload_len; i++)
    {
        printf("%02x ", payload[i]);
        // 16바이트마다 줄 바꿈
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

// 캡처된 패킷을 처리하는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    FILE *log_file = (FILE *)args; // 로그 파일 포인터
    struct ethheader *eth = (struct ethheader *)packet; // 이더넷 헤더 추출

    // 이더넷 타입이 IP(0x0800)인지 확인
    if (ntohs(eth->ether_type) == 0x0800) 
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); // IP 헤더 추출

        // 프로토콜에 따라 적절한 패킷 처리 함수 호출
        if (ip->iph_protocol == IPPROTO_TCP)
        {
            print_tcp_packet(packet, log_file); // TCP 패킷 처리
        }
        else if (ip->iph_protocol == IPPROTO_UDP)
        {
            print_udp_packet(packet, log_file); // UDP 패킷 처리
        }
    }
}

int main()
{
    pcap_t *handle; // 패킷 캡처 핸들
    char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장할 버퍼
    struct bpf_program fp; // BPF 필터 프로그램
    char filter_exp[] = "tcp or udp"; // 필터 표현식
    bpf_u_int32 net; // 네트워크 번호

    // 로그 파일 열기
    FILE *log_file = fopen("packet_log.txt", "w");
    if (log_file == NULL)
    {
        perror("Error opening log file"); // 로그 파일 열기 오류 처리
        return 1;
    }

    // 패킷 캡처 장치 열기
    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf); // 장치 열기 오류 처리
        fclose(log_file);
        return 2;
    }

    // 필터 컴파일
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle)); // 필터 파싱 오류 처리
        fclose(log_file);
        return 2;
    }

    // 필터 설치
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)); // 필터 설치 오류 처리
        fclose(log_file);
        return 2;
    }

    // 패킷 캡처 루프 시작
    pcap_loop(handle, -1, got_packet, (u_char *)log_file);

    // 캡처 핸들 닫기
    pcap_close(handle);

    // 로그 파일 닫기
    fclose(log_file);

    return 0;
}
