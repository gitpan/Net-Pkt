#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)

#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/ioctl.h>

int
netpkt_open_l2(char *interface)
{
   int fd;
   int r;
   int i;
   char buf[1024];
   struct ifreq ifr;
   const int build_eth_hdr = 1;

   /* open first available bpf */
   for (i=0 ; i<255 ; i++) {
      char dev[sizeof "/dev/bpfxxx"];
      memset (dev, '\0', sizeof dev);
      snprintf (dev, sizeof dev - 1, "/dev/bpf%d", i);
      fd = open (dev, O_RDWR);
      if (fd == -1 && errno != EBUSY) {
         memset (buf, '\0', sizeof buf);
         snprintf (buf, sizeof buf - 1, "%s: open: %s: %s: %s\n",
            __FUNCTION__, interface, dev, strerror (errno));
         fprintf (stderr, "%s", buf);
         return 0;
      }
      else if (fd == -1 && errno == EBUSY)
         continue;
      else
         break;
   }
   if (fd == -1) {
      memset (buf, '\0', sizeof buf);
      snprintf (buf, sizeof buf - 1, "%s: %s: can't open any bpf\n",
         __FUNCTION__, interface);
      fprintf (stderr, "%s", buf);
      return 0;
   }

   memset  (&ifr, '\0', sizeof ifr);
   strncpy (ifr.ifr_name, interface, sizeof ifr.ifr_name - 1);

   /* Attach network interface */
   r = ioctl (fd, BIOCSETIF, (caddr_t) &ifr);
   if (r == -1) {
      memset (buf, '\0', sizeof buf);
      snprintf (buf, sizeof buf - 1, "%s: ioctl(BIOCSETIF): %s: %s\n",
         __FUNCTION__, interface, strerror (errno));
      fprintf (stderr, "%s", buf);
      return 0;
   }

   /* Enable Ethernet headers construction */
   r = ioctl (fd, BIOCSHDRCMPLT, &build_eth_hdr);
   if (r == -1) {
      memset (buf, '\0', sizeof buf);
      snprintf (buf, sizeof buf - 1, "%s: ioctl(BIOCSHDRCMPLT): %s: %s\n",
         __FUNCTION__, interface, strerror (errno));
      fprintf (stderr, "%s", buf);
      return 0;
   }

   return fd;
}
#endif /* FreeBSD */


#if defined(__linux__)

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>

int
netpkt_open_l2(char *interface)
{
   int r;
   int fd;
   char buf[1024];
   struct ifreq ifr;

   fd = socket (PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
   if (fd < 0) {
      memset (buf, '\0', sizeof buf);
      snprintf (buf, sizeof buf - 1, "%s: socket: %s: %s\n",
         __FUNCTION__, interface, strerror (errno));
      fprintf (stderr, "%s", buf);
      return 0;
   }

   memset (&ifr, '\0', sizeof ifr);
   strncpy (ifr.ifr_name, interface, sizeof ifr.ifr_name - 1);
   r = ioctl (fd, SIOCGIFHWADDR, &ifr);
   if (r < 0) {
      memset (buf, '\0', sizeof buf);
      snprintf (buf, sizeof buf - 1, "%s: ioctl(SIOCGIFHWADDR): %s: %s\n",
         __FUNCTION__, interface, strerror (errno));
      fprintf (stderr, "%s", buf);
      return 0;
   }

   return fd;
}
#endif /* Linux */

/* All platform supporting libpcap */

#include <pcap.h>

struct pcap_timeval {
   bpf_int32 tv_sec;        /* seconds */
   bpf_int32 tv_usec;       /* microseconds */
};
         
struct pcap_sf_pkthdr {
   struct pcap_timeval ts; /* time stamp */
   bpf_u_int32 caplen;     /* length of portion present */
   bpf_u_int32 len;        /* length this packet (off wire) */
}; 

void
_netpkt_pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
   register FILE *f;
   struct pcap_sf_pkthdr sf_hdr;
   
   f = (FILE *)user;
   sf_hdr.ts.tv_sec  = h->ts.tv_sec;
   sf_hdr.ts.tv_usec = h->ts.tv_usec;
   sf_hdr.caplen     = h->caplen;
   sf_hdr.len        = h->len;

   fwrite(&sf_hdr, sizeof(sf_hdr), 1, f);
   fwrite((char *)sp, h->caplen, 1, f);
   fflush(f);
}

int
netpkt_tcpdump(char *dev, char *file, char *filter, int snaplen, int promisc)
{
   bpf_u_int32        localnet;
   bpf_u_int32        netmask;
   struct bpf_program fcode;
   char               ebuf[PCAP_ERRBUF_SIZE];
   pcap_t            *pd;
   pcap_dumper_t     *p;

   memset(ebuf, 0, sizeof ebuf);
   pd = pcap_open_live(dev, snaplen, promisc, 1000, ebuf);
   if (pd == NULL)
      fprintf(stderr, "%s: pcap_open_live: %s\n", __FUNCTION__, ebuf);
   else if (*ebuf)
      fprintf(stderr, "%s: pcap_open_live: %s\n", __FUNCTION__, ebuf);

   memset(ebuf, 0, sizeof ebuf);
   if (pcap_lookupnet(dev, &localnet, &netmask, ebuf) < 0) {
      localnet = 0;
      netmask = 0;
      fprintf(stderr, "%s: pcap_lookupnet: %s\n", __FUNCTION__, ebuf);
   }

   setuid(getuid());

   if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0) {
      fprintf(stderr, "%s: pcap_compile: %s\n", __FUNCTION__, pcap_geterr(pd));
      return(0);
   }

   if (pcap_setfilter(pd, &fcode) < 0) {
      fprintf(stderr, "%s: pcap_setfilter: %s\n", __FUNCTION__,
         pcap_geterr(pd));
      return(0);
   }

   p = pcap_dump_open(pd, file);
   if (p == NULL) {
      fprintf(stderr, "%s: pcap_dump_open: %s\n", __FUNCTION__,
         pcap_geterr(pd));
      return(0);
   }

   if (pcap_loop(pd, -1, _netpkt_pcap_dump, (u_char *)p) < 0) {
      fprintf(stderr, "%s: pcap_loop: %s\n", __FUNCTION__, pcap_geterr(pd));
      return(0);
   }

   pcap_close(pd);
   return(1);
}
