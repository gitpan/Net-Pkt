typedef struct pcap pcap_t;

int
netpkt_open_l2(char *interface);

int
netpkt_tcpdump(char *dev, char *file, char *filter, int snaplen, int promisc);

FILE *
netpkt_pcap_fp(pcap_t *pd);
