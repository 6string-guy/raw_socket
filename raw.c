#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>


struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return(answer);
}

int main(void) {
    // Payload
    char *data = "Hello, world!"; // Example payload
    int data_len = strlen(data);

    // Create a raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Buffer for the packet
    char packet[4096];

    // Zero out the buffer
    memset(packet, 0, 4096);

    // IP header pointer
    struct iphdr *iph = (struct iphdr *) packet;
    // TCP header pointer
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
    // Data pointer (payload)
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

    // Copy payload into packet buffer
    memcpy(payload, data, data_len);

    struct sockaddr_in dest;
    struct pseudo_header psh;

    // Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len); // Include payload
    iph->id = htonl(54321); // Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Set to 0 before calculating checksum
    iph->saddr = inet_addr("192.168.56.103"); // Source IP
    iph->daddr = inet_addr("192.168.56.101"); // Destination IP

    // Fill in the TCP Header
    tcph->source = htons(1234);
    tcph->dest = htons(80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // TCP header size (no options)
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0; // Will be filled later
    tcph->urg_ptr = 0;

    // IP checksum
    iph->check = csum((unsigned short *) packet, sizeof(struct iphdr));

    // Now the TCP checksum
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + data_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len;
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + data_len);

    tcph->check = csum((unsigned short*) pseudogram, psize);

    // Destination address
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    dest.sin_addr.s_addr = iph->daddr;

    // Inform the kernel that headers are included
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    // Send the packet
    int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
    if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
    } else {
        printf("Packet Sent. Length : %d bytes\n", packet_size);
    }

    free(pseudogram);
    close(sock);

    return 0;
}
