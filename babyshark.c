#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <signal.h>

volatile sig_atomic_t stop_sniffing = 0;

pcap_t *handler;
int total_packets;

void handle_interrupt(int sig) {
  stop_sniffing = 1;
  pcap_breakloop(handler);
}


void pcap_handlerp (u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet_str) {
  int link_t = 0;
  if ((link_t = pcap_datalink(handler)) == PCAP_ERROR) {
    fprintf(stderr, "pcap datalink is not found any interface: %s", pcap_geterr(handler));
  }
  switch(link_t) {
  case DLT_NULL:
    link_t = 4;
    break;
  case DLT_EN10MB:
    link_t = 14;
    break;
  case DLT_SLIP:
    link_t = 24;
    break;
  case DLT_PPP:
    link_t = 24;
    break;
  default:
    printf("cannot recognize any interface.");
  }

  struct ip *ip_header;
  char ip_header_info[255];
  char source_ip[255];
  char dest_ip[255];

  packet_str += link_t;
  ip_header = (struct ip*)packet_str;
  strcpy(source_ip, inet_ntoa(ip_header->ip_src));
  strcpy(dest_ip, inet_ntoa(ip_header->ip_dst));
  sprintf(ip_header_info, "IP Header:\n  IP ID: %d, TTL: %d, Header Length: %d, Total Length: %d \n",
	  ntohs(ip_header->ip_id), ip_header->ip_ttl, 4*ip_header->ip_hl, ntohs(ip_header->ip_len));

  packet_str += 4*ip_header->ip_hl;

  struct icmp* icmp_header;
  struct tcphdr* tcp_header;
  struct udphdr* udp_header;
  switch(ip_header->ip_p) {
  case IPPROTO_TCP:
    tcp_header = (struct tcphdr*)packet_str;
    printf("Protocol: TCP\n");
    printf("Source IP: %s, PORT: %d\nDestination IP: %s, PORT: %d\n",
	   source_ip, ntohs(tcp_header->th_sport),
	   dest_ip, ntohs(tcp_header->th_dport)
	   );
    printf("%s", ip_header_info);
    printf("TCP Header: \n   ");
    printf("Header Length: %d bytes\n", 4*tcp_header->th_off);
    printf("   Flags: ");
    if (tcp_header->th_flags & TH_URG) printf("URG ");
    if (tcp_header->th_flags & TH_ACK) printf("ACK ");
    if (tcp_header->th_flags & TH_PUSH) printf("PUSH ");
    if (tcp_header->th_flags & TH_RST) printf("RST ");
    if (tcp_header->th_flags & TH_SYN) printf("SYN ");
    printf("\nPayload Length: %d\n", (ntohs(ip_header->ip_len) - 4 * ip_header->ip_hl - 4 * tcp_header->th_off));
    printf("------------------------------------\n");
    total_packets++;
    break;

  case IPPROTO_UDP:
    udp_header = (struct udphdr*)packet_str;
    printf("Protocol: UDP\n");
    printf("Source IP: %s, PORT: %d\n Destination IP: %s, PORT: %d\n",
	   source_ip, ntohs(udp_header->uh_sport),
	   dest_ip, ntohs(udp_header->uh_dport)
	   );
    printf("%s", ip_header_info);
    printf("UDP Header: \n   ");
    printf("Length: %d", ntohs(udp_header->uh_ulen));
    printf("\nPayload Length: %d\n", (ntohs(ip_header->ip_len) - 4 * ip_header->ip_hl - 8));
    printf("------------------------------------\n");
    total_packets++;
    break;
    
  case IPPROTO_ICMP:
    icmp_header = (struct icmp*)packet_str;
    printf("Protocol: UDP\n");
    printf("Source IP: %s\n Destination IP: %s\n",
	   source_ip, 
	   dest_ip
	   );
    printf("%s", ip_header_info);
    printf("ICMP Header: \n   ");
    if (icmp_header->icmp_type == 8)
      printf("Type: 8 (Echo Request)");
    else if (icmp_header->icmp_type == 0)
      printf("Type: 0 (Echo Reply)");
    else
      printf("Type: %d (Unknown)", icmp_header->icmp_type);
    printf(", Code: %d\n   Identifier: %d, Sequence Number: %d",
	   icmp_header->icmp_code, ntohs(icmp_header->icmp_hun.ih_idseq.icd_id), ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq));
     printf("\nPayload Length: %d\n", (ntohs(ip_header->ip_len) - 4 * ip_header->ip_hl - 8));
     printf("------------------------------------\n");
     total_packets++;
     break;

  default:
    printf("unrecognized protocol");
    break;
    
  } 
  return;
}

int main (int argc, char *argv[]) {
  signal(SIGINT, handle_interrupt);
  pcap_if_t *alldevs, *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  int packet_count = 0;
  char *filter_text = "";
  int opt;
  char *dev_name;

  while((opt = getopt(argc, argv, "hd:t:e:")) != -1) {
    switch (opt) {
    case 'h':
      printf("Usage: babyshark [-h] [-d device/interface] [-t packet count] [-e expression]");
      return 0;
    case 'd':
      dev_name = optarg;
      break;
    case 't':
      packet_count = atoi(optarg);
      break;
    case 'e':
      filter_text = strdup(optarg);
      break;
    }
  }
  
  if (dev_name == NULL) {
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      fprintf(stderr, "Pcap cannot find any device: %s\n", errbuf);
      return -1;
    }
    dev = alldevs;
    if (dev == NULL) {
      fprintf(stderr, "No device found.\n");
      return -1;
    }
    dev_name = dev->name;
  }
  
  
  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  if ( 
      pcap_lookupnet (dev->name,
                      &netp,
                      &maskp,
                      errbuf) == -1)
    {
      fprintf (stderr, "pcap_lookupnet is failed %s", errbuf);
      if (dev)
        {
          pcap_freealldevs (dev);
        }
      return -1;
    }

  
  handler = pcap_open_live (dev->name, BUFSIZ, 0, 1000, errbuf);
  if (!handler) {
    if (dev) {
	pcap_freealldevs (dev);
      }
    fprintf (stderr, "handler is null %s", errbuf);
    return -1;
  }
  
  struct bpf_program filter;
  if (pcap_compile(handler,&filter, filter_text, 0, maskp) == -1) {
    fprintf(stderr,"Filter Syntax Error : %s\n", pcap_geterr(handler));
    return -1;
  }

  if (pcap_setfilter(handler, &filter) == -1) {
    fprintf(stderr, "Filter setting error: %s", pcap_geterr(handler));
    return -1;
  }
  
  if (pcap_loop(handler, packet_count, pcap_handlerp, (u_char*)NULL)  == -1) {
    fprintf(stderr, "pcap_loop failed: %s\n", errbuf);
    return -1;
  }

  struct pcap_stat st;
  if (pcap_stats(handler, &st) >= 0) {
    printf("\n%d captured\n", total_packets);
    printf("%d received\n", st.ps_recv);
    printf("%d dropped\n\n", st.ps_drop);
  }
  
  
  pcap_freecode(&filter);
  pcap_close(handler);
  if (alldevs) pcap_freealldevs(alldevs);

  return 0;
}
