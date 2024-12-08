#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

// Function to print TCP packet details
void print_tcp_packet(const u_char *packet, FILE *log_file)
{
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned short ip_header_len = ip->iph_ihl * 4;

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // Calculate payload start position and length
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + (tcp->tcp_offx2 >> 4) * 4;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - (tcp->tcp_offx2 >> 4) * 4;

    fprintf(log_file, "\nTCP Packet\n");
    fprintf(log_file, "   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    fprintf(log_file, "   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    fprintf(log_file, "   Source Port: %u\n", ntohs(tcp->tcp_sport));
    fprintf(log_file, "   Destination Port: %u\n", ntohs(tcp->tcp_dport));
    fprintf(log_file, "   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    fprintf(log_file, "   Payload (%d bytes):\n", payload_len);
    for (int i = 0; i < payload_len; i++)
    {
        fprintf(log_file, "%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    fprintf(log_file, "\n");

    // Also print to console
    printf("\nTCP Packet\n");
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("   Source Port: %u\n", ntohs(tcp->tcp_sport));
    printf("   Destination Port: %u\n", ntohs(tcp->tcp_dport));
    printf("   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    printf("   Payload (%d bytes):\n", payload_len);
    for (int i = 0; i < payload_len; i++)
    {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

// Function to print UDP packet details
void print_udp_packet(const u_char *packet, FILE *log_file)
{
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned short ip_header_len = ip->iph_ihl * 4;

    struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // Calculate payload start position and length
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + sizeof(struct udpheader);
    int payload_len = ntohs(udp->udp_ulen) - sizeof(struct udpheader);

    fprintf(log_file, "\nUDP Packet\n");
    fprintf(log_file, "   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    fprintf(log_file, "   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    fprintf(log_file, "   Source Port: %u\n", ntohs(udp->udp_sport));
    fprintf(log_file, "   Destination Port: %u\n", ntohs(udp->udp_dport));
    fprintf(log_file, "   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    fprintf(log_file, "   Payload (%d bytes):\n", payload_len);
    for (int i = 0; i < payload_len; i++)
    {
        fprintf(log_file, "%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            fprintf(log_file, "\n");
    }
    fprintf(log_file, "\n");

    // Also print to console
    printf("\nUDP Packet\n");
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("   Source Port: %u\n", ntohs(udp->udp_sport));
    printf("   Destination Port: %u\n", ntohs(udp->udp_dport));
    printf("   Packet Length: %u bytes\n", ntohs(ip->iph_len));
    printf("   Payload (%d bytes):\n", payload_len);
    for (int i = 0; i < payload_len; i++)
    {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

// Callback function for each captured packet
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    FILE *log_file = (FILE *)args;
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) // Check for IP packets
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP)
        {
            print_tcp_packet(packet, log_file);
        }
        else if (ip->iph_protocol == IPPROTO_UDP)
        {
            print_udp_packet(packet, log_file);
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";
    bpf_u_int32 net;

    // Open log file
    FILE *log_file = fopen("packet_log.txt", "w");
    if (log_file == NULL)
    {
        perror("Error opening log file");
        return 1;
    }

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        fclose(log_file);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fclose(log_file);
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        fclose(log_file);
        return 2;
    }

    pcap_loop(handle, -1, got_packet, (u_char *)log_file);

    pcap_close(handle);

    // Close the log file
    fclose(log_file);

    return 0;
}
