#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
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
