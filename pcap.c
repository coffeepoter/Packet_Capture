#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "myheader.h"

FILE *log_file; // 전역 변수로 선언

// OpenSSL 라이브러리 초기화
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// OpenSSL 라이브러리 청소
void cleanup_openssl() {
    EVP_cleanup();
}

// SSL 세션 초기화
SSL_CTX *initialize_ssl(const char *private_key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key from %s\n", private_key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// SSL/TLS 페이로드 복호화
void decrypt_ssl_payload(const u_char *payload, int payload_len, SSL_CTX *ctx) {
    BIO *bio = BIO_new_mem_buf((void *)payload, payload_len);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        return;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL structure\n");
        BIO_free(bio);
        return;
    }

    SSL_set_bio(ssl, bio, bio);

    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }

    char buffer[1024];
    int len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        fprintf(log_file, "\n[Decrypted SSL/TLS Payload]\n%s\n", buffer);
        printf("\n[Decrypted SSL/TLS Payload]\n%s\n", buffer);
    } else {
        fprintf(stderr, "Failed to decrypt SSL payload\n");
    }

    SSL_free(ssl);
}

// SSL/TLS 메타데이터 출력
void print_ssl_metadata(const u_char *payload, int payload_len, SSL_CTX *ctx) {
    if (payload_len < 5) {
        fprintf(log_file, "\n[SSL/TLS] Payload too short to parse.\n");
        printf("\n[SSL/TLS] Payload too short to parse.\n");
        return;
    }

    const u_char content_type = payload[0];
    const u_char version_major = payload[1];
    const u_char version_minor = payload[2];

    fprintf(log_file, "\n[SSL/TLS Packet]\n");
    fprintf(log_file, "   Content Type: %u\n", content_type);
    fprintf(log_file, "   Version: %u.%u\n", version_major, version_minor);
    fprintf(log_file, "   Payload Length: %d bytes\n", payload_len);

    printf("\n[SSL/TLS Packet]\n");
    printf("   Content Type: %u\n", content_type);
    printf("   Version: %u.%u\n", version_major, version_minor);
    printf("   Payload Length: %d bytes\n", payload_len);

    if (content_type == 22) { // Handshake
        fprintf(log_file, "   Handshake Type: %u\n", payload[5]);
        printf("   Handshake Type: %u\n", payload[5]);
    }

    decrypt_ssl_payload(payload, payload_len, ctx);
}

// TCP 패킷 출력
void print_tcp_packet(const u_char *packet, SSL_CTX *ctx) {
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned short ip_header_len = ip->iph_ihl * 4;

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // 페이로드 시작 위치 및 길이 계산
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + (tcp->tcp_offx2 >> 4) * 4;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - (tcp->tcp_offx2 >> 4) * 4;

    fprintf(log_file, "\nTCP Packet\n");
    fprintf(log_file, "   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    fprintf(log_file, "   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    fprintf(log_file, "   Source Port: %u\n", ntohs(tcp->tcp_sport));
    fprintf(log_file, "   Destination Port: %u\n", ntohs(tcp->tcp_dport));
    fprintf(log_file, "   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    fprintf(log_file, "   Payload (%d bytes):\n", payload_len);
    
    for (int i = 0; i < payload_len; i++) {
        fprintf(log_file, "%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    fprintf(log_file, "\n");

    printf("\nTCP Packet\n");
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("   Source Port: %u\n", ntohs(tcp->tcp_sport));
    printf("   Destination Port: %u\n", ntohs(tcp->tcp_dport));
    printf("   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    printf("   Payload (%d bytes):\n", payload_len);
    
    for (int i = 0; i < payload_len; i++) {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");

    if (ntohs(tcp->tcp_dport) == 443 || ntohs(tcp->tcp_sport) == 443) {
        print_ssl_metadata(payload, payload_len, ctx);
    }
}

// UDP 패킷 출력
void print_udp_packet(const u_char *packet) {
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned short ip_header_len = ip->iph_ihl * 4;

    struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + sizeof(struct udpheader);
    int payload_len = ntohs(udp->udp_ulen) - sizeof(struct udpheader);

    fprintf(log_file, "\nUDP Packet\n");
    fprintf(log_file, "   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    fprintf(log_file, "   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    fprintf(log_file, "   Source Port: %u\n", ntohs(udp->udp_sport));
    fprintf(log_file, "   Destination Port: %u\n", ntohs(udp->udp_dport));
    fprintf(log_file, "   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    fprintf(log_file, "   Payload (%d bytes):\n", payload_len);
    
    for (int i = 0; i < payload_len; i++) {
        fprintf(log_file, "%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    fprintf(log_file, "\n");

    // 콘솔에도 출력
    printf("\nUDP Packet\n");
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("   Source Port: %u\n", ntohs(udp->udp_sport));
    printf("   Destination Port: %u\n", ntohs(udp->udp_dport));
    printf("   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    printf("   Payload (%d bytes):\n", payload_len);
    
    for (int i = 0; i < payload_len; i++) {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

// 각 패킷을 처리하는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    SSL_CTX *ctx = (SSL_CTX *)args;  // ctx를 인수로 받도록 수정
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷 확인
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            print_tcp_packet(packet, ctx); // ctx 전달
        } else if (ip->iph_protocol == IPPROTO_UDP) {
            print_udp_packet(packet);
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";
    bpf_u_int32 net;

    // OpenSSL 초기화
    initialize_openssl();

    // SSL_CTX 초기화
    SSL_CTX *ctx = initialize_ssl("server.key");
    if (!ctx) {
        fprintf(stderr, "Failed to initialize SSL context\n");
        return 1;
    }

    // 로그 파일 열기
    log_file = fopen("packet_log.txt", "w");
    if (log_file == NULL) {
        perror("Error opening log file");
        cleanup_openssl();
        return 1;
    }

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        fclose(log_file);
        cleanup_openssl();
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fclose(log_file);
        cleanup_openssl();
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fclose(log_file);
        cleanup_openssl();
        return 2;
    }

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, (u_char *)ctx); // ctx를 인수로 전달

    // 자원 청소
    pcap_freecode(&fp); // 컴파일된 필터 메모리 해제
    pcap_close(handle);
    fclose(log_file);
    cleanup_openssl();
    SSL_CTX_free(ctx); // SSL_CTX 청소

    return 0;
}
