/*
    MODULE -- iface and capture functions

    Copyright (C) Alberto Ornaghi

    $Id: capture.c 3422 2011-02-09 12:55:25Z alor $
*/

#include <main.h>
#include <decode.h>
#include <threads.h>
#include <capture.h>
#include <ui.h>
#include <inet.h>

#include <pcap/pcap.h>
#ifdef OS_LINUX
   /* for wireless extensions */
   #include <iwlib.h>
#endif

#if defined(OS_LINUX)
   /* LINUX needs 1 */
   #define PCAP_TIMEOUT 1
   #include <net/if.h>
   #include <sys/ioctl.h>
#elif defined(OS_SOLARIS)
   /* SOLARIS needs > 1 */
   #define PCAP_TIMEOUT 10
#else
   /* FREEBSD needs 1 */
   /* MACOSX  needs 1 */
   #define PCAP_TIMEOUT 10
#endif

/* globals */

/* protos */

void capture_init(void);
void capture_close(void);
void capture_start(void);
void capture_stop(void);

void capture_getifs(void);
int is_pcap_file(char *file, char *errbuf);

int iface_is_wireless(char *iface);
int iface_set_status(char *iface, u_char status);
int iface_set_monitor(char *iface);
int iface_set_channel(char *iface, int channel);

/*******************************************/

/*
 * set up the pcap to capture from the specified interface
 * set up even the first dissector by looking at DLT_*
 */

void capture_init(void)
{
   pcap_t *pd;
   struct bpf_program bpf;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];

   /*
    * if the user didn't specified the interface,
    * we have to found one...
    */
   if (!GBL_OPTIONS->read && GBL_OPTIONS->Siface == NULL && GBL_CONF->sniffing_iface == NULL) {
      char *ifa = pcap_lookupdev(pcap_errbuf);
      ON_ERROR(ifa, NULL, "No suitable interface found...");

      GBL_OPTIONS->Siface = strdup(ifa);
   }

   /* if the iface is not set on command line, get it form the file */
   if (GBL_CONF->sniffing_iface && GBL_OPTIONS->Siface == NULL) {
      GBL_OPTIONS->Siface = GBL_CONF->sniffing_iface;
      GBL_OPTIONS->Siface_chan = GBL_CONF->sniffing_iface_channel;
   }

   if (GBL_OPTIONS->Siface)
      DEBUG_MSG(D_INFO, "capture_init %s", GBL_OPTIONS->Siface);
   else
      DEBUG_MSG(D_INFO, "capture_init (no interface)");


   if (GBL_OPTIONS->read) {
      USER_MSG("Reading from %s...\n", GBL_OPTIONS->pcapfile_in);
   } else {
      if (GBL_OPTIONS->Siface_chan)
         USER_MSG("Listening on %s (channel %d)...\n", GBL_OPTIONS->Siface, GBL_OPTIONS->Siface_chan);
      else
         USER_MSG("Listening on %s...\n", GBL_OPTIONS->Siface);
   }

   /* set the snaplen to maximum */
   GBL_PCAP->snaplen = 2048;

   /* open the interface from GBL_OPTIONS (user specified) */
   if (GBL_OPTIONS->read) {
      pd = pcap_open_offline(GBL_OPTIONS->pcapfile_in, pcap_errbuf);
   } else {
      // pd = pcap_open_live(GBL_OPTIONS->Siface, GBL_PCAP->snaplen, 1, PCAP_TIMEOUT, pcap_errbuf);
      /* slice the pcap_open_live function in pieces to insert the pcap_set_rfmon() */
      pd = pcap_create(GBL_OPTIONS->Siface, pcap_errbuf);
      ON_ERROR(pd, NULL, "pcap_create: %s", pcap_errbuf);

      if (pcap_set_snaplen(pd, GBL_PCAP->snaplen) < 0)
         FATAL_ERROR("Cannot set snaplen on [%s]", GBL_OPTIONS->Siface);

      DEBUG_MSG(D_INFO, "Activating promisc mode on [%s]...", GBL_OPTIONS->Siface);
      if (pcap_set_promisc(pd, 1) < 0)
         FATAL_ERROR("ERROR: Cannot enable promisc mode [%s]", pcap_geterr(pd));

      /* if the interface is wireless, enable the monitor mode */
      if (iface_is_wireless(GBL_OPTIONS->Siface)) {
         DEBUG_MSG(D_INFO, "Activating monitor mode on [%s]...", GBL_OPTIONS->Siface);
#if 0
         /*
          * NOTICE: for some awkward reason, this does not work !!
          * in some case the interface DLT si set to NULL (BSD loopback)
          * in other cases a mon0 interface is created...
          * don't mess with this and use the "granny-style" monitor mode
          */
         /* try first with the gentle manner... */
         if (pcap_can_set_rfmon(pd)) {
            if (pcap_set_rfmon(pd, 1) < 0)
               DEBUG_MSG(D_ERROR, "ERROR: Monitor mode failed [%s]", pcap_geterr(pd));
         } else {
            /* then try the rude way */
            DEBUG_MSG(D_INFO, "Cannot set the monitor mode, trying bringing it down and up again...");
#endif
            do {
               /* bring the interface DOWN */
               if (iface_set_status(GBL_OPTIONS->Siface, IFACE_DOWN) != ESUCCESS) {
                  DEBUG_MSG(D_ERROR, "ERROR: Failed to bring [%s] DOWN", GBL_OPTIONS->Siface);
                  break;
               }
               /* try to set the rfmon now */
               if (iface_set_monitor(GBL_OPTIONS->Siface) < 0) {
                  DEBUG_MSG(D_ERROR, "ERROR: Monitor mode failed [%s]", pcap_geterr(pd));
                  /* don't break here, we need to restore the interface in UP state */
               }
               /* bring the interface UP */
               if (iface_set_status(GBL_OPTIONS->Siface, IFACE_UP) != ESUCCESS) {
                  FATAL_ERROR("Failed to bring [%s] UP, cannot continue", GBL_OPTIONS->Siface);
                  break;
               }
            } while (0);
#if 0
         }
#endif
         /* set the channel to listen on */
         if (GBL_OPTIONS->Siface_chan) {
            DEBUG_MSG(D_INFO, "Setting wireless channel %d on [%s]...", GBL_OPTIONS->Siface_chan, GBL_OPTIONS->Siface);
            if (iface_set_channel(GBL_OPTIONS->Siface, GBL_OPTIONS->Siface_chan) < 0) {
               DEBUG_MSG(D_ERROR, "ERROR: Failed to set channel %d [%s]", GBL_OPTIONS->Siface_chan, pcap_geterr(pd));
            }
         }
      }

      if (pcap_set_timeout(pd, PCAP_TIMEOUT) < 0)
         FATAL_ERROR("Cannot set timeout to %d on [%s]", PCAP_TIMEOUT, GBL_OPTIONS->Siface);

      if (pcap_activate(pd) < 0)
         FATAL_ERROR("Cannot activate [%s]", GBL_OPTIONS->Siface);
   }
   ON_ERROR(pd, NULL, "pcap_open: %s", pcap_errbuf);

   /*
    * update to the reap assigned snapshot.
    * this may be different reading from files
    */
   DEBUG_MSG(D_INFO, "requested snapshot: %d assigned: %d", GBL_PCAP->snaplen, pcap_snapshot(pd));
   GBL_PCAP->snaplen = pcap_snapshot(pd);

   /* get the file size */
   if (GBL_OPTIONS->read) {
      struct stat st;
      fstat(fileno(pcap_file(pd)), &st);
      GBL_PCAP->dump_size = st.st_size;
   }

   /* set the pcap filters */
   if (GBL_PCAP->filter != NULL && strcmp(GBL_PCAP->filter, "")) {

      DEBUG_MSG(D_INFO, "pcap_filter: %s", GBL_PCAP->filter);

      if (pcap_compile(pd, &bpf, GBL_PCAP->filter, 1, 0) < 0)
         ERROR_MSG("%s", pcap_errbuf);

      if (pcap_setfilter(pd, &bpf) == -1)
         ERROR_MSG("pcap_setfilter");

      pcap_freecode(&bpf);
   }

   /* set the right dlt type for the iface */
   GBL_PCAP->dlt = pcap_datalink(pd);

   DEBUG_MSG(D_INFO, "capture_init: %s [%d]", pcap_datalink_val_to_description(GBL_PCAP->dlt), GBL_PCAP->dlt);
   USER_MSG("Link layer is %s\n", pcap_datalink_val_to_description(GBL_PCAP->dlt));

   /* check if we support this media */
   if (get_decoder(LINK_LAYER, GBL_PCAP->dlt) == NULL) {
      if (GBL_OPTIONS->read)
         FATAL_ERROR("Dump file not supported [%02X](%s)", GBL_PCAP->dlt, pcap_datalink_val_to_description(GBL_PCAP->dlt));
      else
         FATAL_ERROR("Network Inteface \"%s\" not supported [%02X](%s)", GBL_OPTIONS->Siface, GBL_PCAP->dlt, pcap_datalink_val_to_description(GBL_PCAP->dlt));
   }

   /* set the global descriptor for the capture interface */
   GBL_PCAP->pcap = pd;

   /* on exit clean up the structures */
   atexit(capture_close);

}


void capture_close(void)
{
   if (GBL_PCAP->pcap)
      pcap_close(GBL_PCAP->pcap);

   DEBUG_MSG(D_DEBUG, "ATEXIT: capture_closed");
}


void capture_start(void)
{
   int ret;

   DEBUG_MSG(D_DEBUG, "capture_start");

   /*
    * infinite loop
    * dispatch packets to decode
    */
   ret = pcap_loop(GBL_PCAP->pcap, -1, decode_captured, NULL);
   ON_ERROR(ret, -1, "Error while capturing: %s", pcap_geterr(GBL_PCAP->pcap));

   DEBUG_MSG(D_DEBUG, "capture_start: [%d] exited the infinite loop", ret);
}

void capture_stop(void)
{
   DEBUG_MSG(D_DEBUG, "capture_stop");

   pcap_breakloop(GBL_PCAP->pcap);
}

/*
 * get the list of all network interfaces
 */
void capture_getifs(void)
{
   pcap_if_t *ifs;
   pcap_if_t *dev, *pdev, *ndev;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];

   DEBUG_MSG(D_DEBUG, "capture_getifs");

   /* retrieve the list */
   if (pcap_findalldevs(&ifs, pcap_errbuf) == -1)
      ERROR_MSG("%s", pcap_errbuf);

   /* analize the list and remove unwanted entries */
   for (pdev = dev = ifs; dev != NULL; dev = ndev) {

      /* the next entry in the list */
      ndev = dev->next;

      /* set the description for the local loopback */
      if (dev->flags & PCAP_IF_LOOPBACK) {
         SAFE_FREE(dev->description);
         dev->description = strdup("Local Loopback");
      }

      /* fill the empty descriptions */
      if (dev->description == NULL)
         dev->description = dev->name;

      /* remove the pseudo device 'any' */
      if (!strcmp(dev->name, "any")) {
         /* check if it is the first in the list */
         if (dev == ifs)
            ifs = ndev;
         else
            pdev->next = ndev;

         SAFE_FREE(dev->name);
         SAFE_FREE(dev->description);
         SAFE_FREE(dev);

         continue;
      }

      /* remember the previous device for the next loop */
      pdev = dev;

      DEBUG_MSG(D_INFO, "capture_getifs: [%s] %s", dev->name, dev->description);
   }

}

/*
 * check if the given file is a pcap file
 */
int is_pcap_file(char *file, char *errbuf)
{
   pcap_t *pd;

   pd = pcap_open_offline(file, errbuf);
   if (pd == NULL)
      return -EINVALID;

   pcap_close(pd);

   return ESUCCESS;
}

/*
 * check if the interface is wireless
 */
int iface_is_wireless(char *iface)
{
#ifdef OS_MACOSX
   return 0;
#endif
#ifdef OS_LINUX
   struct ifreq ifr;
   int sk;

   if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      return 0;

   strncpy(ifr.ifr_name, iface, IFNAMSIZ);

   /* if the interface does not have a wireless name, it is not wireless :) */
   if (ioctl(sk, SIOCGIWNAME, &ifr) < 0) {
      close(sk);
      return 0;
   }

   close(sk);
   return 1;
#endif
}

/*
 * set the interface status
 */
int iface_set_status(char *iface, u_char status)
{
#ifdef OS_MACOSX
   return -EFAILURE;
#endif
#ifdef OS_LINUX
   struct ifreq ifr;
   int sk;

   if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      return -EFAILURE;

   strncpy(ifr.ifr_name, iface, IFNAMSIZ);

   /* get the current flags */
   if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
      close(sk);
      return -EFAILURE;
   }

   strncpy(ifr.ifr_name, iface, IFNAMSIZ);

   switch(status) {
      case IFACE_UP:
         ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
         break;
      case IFACE_DOWN:
         ifr.ifr_flags &= ~IFF_UP;
         break;
   }

   /* set the new one */
   if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0) {
      close(sk);
      return -EFAILURE;
   }

   close(sk);
   return ESUCCESS;
#endif
}


/*
 * set the interface in monitor mode
 */
int iface_set_monitor(char *iface)
{
#ifdef OS_MACOSX
   return -EFAILURE;
#endif
#ifdef OS_LINUX
   struct iwreq wrq;
   int sk;

   if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      return -EFAILURE;

   strncpy(wrq.ifr_name, iface, IFNAMSIZ);

   /* magic number for monitor mode
    *
    * the values come from:
    *  { "Auto", "Ad-Hoc", "Managed", "Master", "Repeater", "Secondary", "Monitor", "Unknown/bug" }
    */
   wrq.u.mode = 6;

   if (ioctl(sk, SIOCSIWMODE, &wrq) < 0) {
      close(sk);
      return -EFAILURE;
   }

   close(sk);
   return ESUCCESS;
#endif
}

/*
 * set the interface channel (of frequence)
 */
int iface_set_channel(char *iface, int channel)
{
#ifdef OS_MACOSX
   return -EFAILURE;
#endif
#ifdef OS_LINUX
   struct iwreq wrq;
   int sk;

   if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      return -EFAILURE;

   strncpy(wrq.ifr_name, iface, IFNAMSIZ);

   wrq.u.freq.flags = IW_FREQ_FIXED;
   /* this way we support only channels and not real freqs */
   wrq.u.freq.m = channel;
   wrq.u.freq.e = 0;

   if (ioctl(sk, SIOCSIWFREQ, &wrq) < 0) {
      close(sk);
      return -EFAILURE;
   }

   close(sk);
   return ESUCCESS;
#endif
}


/* EOF */

// vim:ts=3:expandtab

