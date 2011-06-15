/*
    MODULE -- network configuration module (RNC)

    Copyright (C) Alberto Ornaghi

    $Id: netconf.c 3558 2011-06-07 10:59:30Z alor $
*/

#include <main.h>
#include <file.h>
#include <netconf.h>
#include <threads.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <netdb.h>
#include <signal.h>
#include <sys/statvfs.h>

/* globals */


/* protos */

void netconf_start(void);
MY_THREAD_FUNC(rnc_communicator);
//static int tcp_connect(char *host, int port);
//static int tcp_accept(int sock);
int ssl_proto_read(BIO *ssl, void *buf, int num);
int ssl_proto_write(BIO *ssl, void *buf, int num);
void rnc_handleproto(BIO *ssl);
int rnc_sendversion(BIO *ssl);
int rnc_sendmonitor(BIO *ssl, char *status, char *desc);
int rnc_retrieveconf(BIO *ssl);
int rnc_sendlogs(BIO *ssl);
void get_system_stats(u_int *disk, u_int *cpu, u_int *pcpu);

/************************************************/

void netconf_start(void)
{
   /* check when to not initialize the proxy */
   if (GBL_OPTIONS->read) {
      DEBUG_MSG(D_INFO, "netconf_start: skipping... (reading offline)");
      return;
   }

   my_thread_new("netconf", "RNC communication module", &rnc_communicator, NULL);
}

MY_THREAD_FUNC(rnc_communicator)
{
   SSL_CTX *ctx;
   SSL *ssl;
   BIO *sbio, *abio, *cbio;
   char *certfile;
   char listen_port[32];

   /* initialize the thread */
   my_thread_init();

   SSL_library_init();
   SSL_load_error_strings();
   OpenSSL_add_all_algorithms();

   /* create the SSL stuff */
   ctx = SSL_CTX_new(SSLv23_server_method());

   certfile = get_path("etc", "ca.pem");

   if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) == 0)
      ERROR_MSG("Cannot load the certificate from %s", certfile);

   if (SSL_CTX_use_PrivateKey_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0)
      ERROR_MSG("Cannot load the private key from %s", certfile);

   if (SSL_CTX_check_private_key(ctx) <= 0)
      ERROR_MSG("Cannot invalid private key from %s", certfile);

   SAFE_FREE(certfile);

   DEBUG_MSG(D_DEBUG, "SSL_CTX initialized");

   /* New SSL BIO setup as server */
   sbio = BIO_new_ssl(ctx, 0);

   BIO_get_ssl(sbio, &ssl);

   if (!ssl)
      ERROR_MSG("Cannot inizialize SSL");

   /* Don't want any retries */
   SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

   /* listen on port */
   snprintf(listen_port, sizeof(listen_port), "0.0.0.0:%d", GBL_NETCONF->rnc_port);
   abio = BIO_new_accept(listen_port);

   /* reuse the address */
   BIO_set_bind_mode(abio, BIO_BIND_REUSEADDR);

   BIO_set_accept_bios(abio, sbio);

   /* First call to BIO_accept() sets up accept BIO */
   if (BIO_do_accept(abio) <= 0)
      ERROR_MSG("Cannot bind port %d for RNC communication", GBL_NETCONF->rnc_port);
   else
      DEBUG_MSG(D_INFO, "Server listening on port %d", GBL_NETCONF->rnc_port);

   /* main loop waiting to be contacted by RNC */
   LOOP {

      /* Wait for incoming connection */
      if (BIO_do_accept(abio) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot perform BIO_do_accept");
         continue;
      }

      /* get the connected client */
      cbio = BIO_pop(abio);

      if (BIO_do_handshake(cbio) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot handshake SSL");
         continue;
      }

      /* handle the communication with the RNC */
      rnc_handleproto(cbio);

      /* close the connection */
      BIO_ssl_shutdown(cbio);
      (void) BIO_flush(cbio);
      BIO_free_all(cbio);

      DEBUG_MSG(D_DEBUG, "Closing connection");
   }

   SSL_CTX_free(ctx);
   BIO_free(abio);
   BIO_free(sbio);

   /* NEVER REACHED */
   return NULL;
}

#if 0
static int tcp_connect(char *host, int port)
{
   struct hostent *hp;
   struct sockaddr_in addr;
   int sock;

   if ( !(hp = gethostbyname(host)) ) {
      DEBUG_MSG(D_ERROR, "Could not resolve host [%s]", host);
      return -1;
   }

   memset(&addr, 0, sizeof(addr));

   addr.sin_addr = *(struct in_addr*)
   hp->h_addr_list[0];
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);

   if ((sock = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP)) < 0) {
      DEBUG_MSG(D_ERROR, "Couldn't create socket [%s:%d]", host, port);
      return -1;
   }

   if (connect(sock,(struct sockaddr *)&addr, sizeof(addr)) < 0) {
      DEBUG_MSG(D_ERROR, "Couldn't connect socket [%s:%d]", host, port);
      return -1;
   }

   return sock;
}

static int tcp_accept(int sock)
{
   struct sockaddr_in caddr;
   u_int len = sizeof(struct sockaddr);
   fd_set  fdread;
   struct timeval tv;
   int ret;
   int csock;

   FD_ZERO(&fdread);
   FD_SET(sock, &fdread);
   memset(&caddr, 0, sizeof(caddr));

   /* set the timeout */
   tv.tv_sec = 0;
   tv.tv_usec = 0;

   ret = select(FOPEN_MAX, &fdread, (fd_set *)NULL, (fd_set *)NULL, NULL /*&tv*/);

   if (ret == 0) {
      /* timeout occurred. return false to let the main thread do other things... */
      return 0;
   } else if (ret == -1) {
      DEBUG_MSG(D_ERROR, "tcp_accept - select socket error [%d]", errno);
      return 0;
   }

   csock = accept(sock, (struct sockaddr *)&caddr, &len);

   if (csock == -1 ) {
      DEBUG_MSG(D_ERROR, "tcp_accept - invalid socket [%d]", errno);
      return 0;
   } else {
      DEBUG_MSG(D_DEBUG, "New connection from %s", inet_ntoa(caddr.sin_addr));
      return csock;
   }

   return 0;
}
#endif

int ssl_proto_read(BIO *ssl, void *buf, int num)
{
   int read = 0;
   int len;
   do {
      len = BIO_read(ssl, (char *)buf + read, num - read);
      if (len <= 0) {
         break;
      }
      read += len;
   } while (read < num);

   return read;
}

int ssl_proto_write(BIO *ssl, void *buf, int num)
{
   int written = 0;
   int len;

   do {
      len = BIO_write(ssl, (char *)buf + written, num - written);
      if (len <= 0) {
         break;
      }
      written += len;
   } while (written < num);

   return written;
}


void rnc_handleproto(BIO *ssl)
{
   RncProtoHeader pheader;
   RncProtoLogin plogin;
   int ret;
   char descr[1024];

   DEBUG_MSG(D_DEBUG, "Handling connection from RNC");

   /* read the login from RNC */
   if ( (ret = ssl_proto_read(ssl, &pheader, sizeof(pheader))) <= 0) {
      DEBUG_MSG(D_ERROR, "Cannot read from RNC");
      return;
   }

   /* check if the command is correct */
   if (ret < (int)sizeof(RncProtoHeader) || pheader.code != RNC_PROTO_LOGIN) {
      DEBUG_MSG(D_ERROR, "Invalid login authentication");
      return;
   }

   /* check if the signature is correct. otherwise reply with NO */
   ret = ssl_proto_read(ssl, &plogin, sizeof(plogin));
   if (ret < (int)sizeof(RncProtoLogin) || memcmp(plogin.sign, GBL_NETCONF->rnc_sign, RNC_SIGN_LEN)) {
      DEBUG_MSG(D_ERROR, "Invalid RNC authentication [%.32s] bytes %d expected %d", plogin.sign, ret, sizeof(RncProtoLogin));
      pheader.code = RNC_PROTO_NO;
      pheader.size = 0;
      ssl_proto_write(ssl, &pheader, sizeof(pheader));
      return;
   }

   pheader.code = RNC_PROTO_OK;
   pheader.size = 0;
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0) {
      DEBUG_MSG(D_ERROR, "Cannot write to RNC");
      return;
   }

   DEBUG_MSG(D_DEBUG, "RNC authenticated and connected");

   /* send monitor status */
   if (rnc_sendversion(ssl) < 0) {
      DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (monitor)");
      return;
   }

   /* prepare the string for the monitor */
   if (GBL_NET->network_error) {
      /* send monitor status */
      if (rnc_sendmonitor(ssl, "KO", "PROXY_IP is invalid, please fix the configuration...") < 0) {
         DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (monitor)");
         return;
      }
   } else {
      snprintf(descr,sizeof(descr), "Active users: %u of %u   Redirected FQDN: %u   Redirected URL: %u   File Infected: %u",
            (u_int)GBL_STATS->active_users,
            (u_int)GBL_STATS->tot_users,
            (u_int)GBL_STATS->redir_fqdn,
            (u_int)GBL_STATS->redir_url,
            (u_int)GBL_STATS->inf_files);

      /* send monitor status */
      if (rnc_sendmonitor(ssl, "OK", descr) < 0) {
         DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (monitor)");
         return;
      }
   }

   /* retrieve new conf (if any) */
   if ((ret = rnc_retrieveconf(ssl)) < 0) {
      DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (config)");
      return;
   }

   /* check if there are new configs */
   if (ret) {
      DEBUG_MSG(D_INFO, "Received new configuration(s), sending signal to reload them...");

      /* reload the new config, the signal handler will reload them */
      kill(getpid(), SIGHUP);

   } else {
      DEBUG_MSG(D_DEBUG, "NO new configuration this time...");
   }

   /* send cached logs */
   if ((ret = rnc_sendlogs(ssl)) < 0) {
      DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (logs)");
      return;
   }

   /* send BYE to RNC */
   pheader.code = RNC_PROTO_BYE;
   pheader.size = 0;

   ssl_proto_write(ssl, &pheader, sizeof(pheader));

   /* disconnect */
}


int rnc_sendversion(BIO *ssl)
{
   RncProtoHeader pheader;
   RncProtoVersion pversion;

   memset(&pheader, 0, sizeof(pheader));
   memset(&pversion, 0, sizeof(pversion));

   /* header parameters */
   pheader.code = RNC_PROTO_VERSION;
   pheader.size = sizeof(pversion);

   /* monitor parameters */
   snprintf(pversion.version, sizeof(pversion.version), "%s", GBL_RCS_VERSION);

   DEBUG_MSG(D_DEBUG, "Sending version information to RNC [%s]", GBL_RCS_VERSION);

   /* send header */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* monitor part */
   if (ssl_proto_write(ssl, &pversion, sizeof(pversion)) <= 0)
      return -1;

   /* read the response from RNC */
   if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   if (pheader.code != RNC_PROTO_OK)
      return -1;

   return 0;
}



int rnc_sendmonitor(BIO *ssl, char *status, char *desc)
{
   RncProtoHeader pheader;
   RncProtoMonitor pmonitor;

   memset(&pheader, 0, sizeof(pheader));
   memset(&pmonitor, 0, sizeof(pmonitor));

   /* header parameters */
   pheader.code = RNC_PROTO_MONITOR;
   pheader.size = sizeof(pmonitor);

   /* monitor parameters */
   snprintf(pmonitor.status, sizeof(pmonitor.status), "%s", status);
   get_system_stats(&pmonitor.disk, &pmonitor.cpu, &pmonitor.pcpu);
   snprintf(pmonitor.desc, sizeof(pmonitor.desc), "%s", desc);

   DEBUG_MSG(D_DEBUG, "Sending monitor information to RNC [%s]", desc);

   /* send header */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* monitor part */
   if (ssl_proto_write(ssl, &pmonitor, sizeof(pmonitor)) <= 0)
      return -1;

   /* read the response from RNC */
   if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   if (pheader.code != RNC_PROTO_OK)
      return -1;

   return 0;
}


int rnc_retrieveconf(BIO *ssl)
{
   FILE *fc;
   RncProtoHeader pheader;
   RncProtoConfig pconfig;
   int found = 0;
   char *conf;

   /* header parameters */
   pheader.code = RNC_PROTO_CONF;
   pheader.size = 0;

   /* send request to check if there is new config */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* loop to receive the new conf */
   LOOP {
      memset(&pheader, 0, sizeof(pheader));
      memset(&pconfig, 0, sizeof(pconfig));

      /* read the response from RNC */
      if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
         break;

      /* there is NOT a new config */
      if (pheader.code != RNC_PROTO_CONF)
         break;

      /* retrieve the config header */
      if (ssl_proto_read(ssl, &pconfig, sizeof(pconfig)) <= 0)
         break;

      /* allocate the buffer and read the conf from RNC */
      SAFE_CALLOC(conf, pconfig.size, sizeof(char));
      if (ssl_proto_read(ssl, conf, pconfig.size) <= 0)
         break;

      DEBUG_MSG(D_INFO, "Received new config file [%s]", pconfig.filename);

      /* open the config file for writing */
      fc = open_data("etc", pconfig.filename, FOPEN_WRITE_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", pconfig.filename);

      /* dump the content of the buffer received from RNC into the file */
      if (fwrite(conf, sizeof(char), pconfig.size, fc) < pconfig.size)
         DEBUG_MSG(D_ERROR, "Cannot write conf file [%s]", pconfig.filename);

      DEBUG_MSG(D_DEBUG, "Config file [%s] written (%d bytes)", pconfig.filename, pconfig.size);

      fclose(fc);

      /* if the file is a ZIP archive, extract it */
      if (!strcasecmp(pconfig.filename + strlen(pconfig.filename) - 4, ".zip")) {
         char *path, *dir, *p;
         char argv[1024];
         int ret;

         /* get the path of the file */
         if ((path = get_path("etc", pconfig.filename)) == NULL)
            continue;

         dir = strdup(path);

         /* trim the filename, get the dirname */
         if ((p = strrchr(dir, '/')) != NULL)
            *p = 0;

         /* clean the vectors directory */
         snprintf(argv, sizeof(argv), "/bin/rm -f %s/vectors/*", dir);

         DEBUG_MSG(D_INFO, "Cleaning vectors directory...");
         /* execute the command */
         ret = system(argv);
         if (ret == -1 || ret == 127)
            DEBUG_MSG(D_ERROR, "Clean failed");

         /* prepare the commandline for unzip */
         snprintf(argv, sizeof(argv), "/usr/bin/unzip -o %s -d %s", path, dir);

         DEBUG_MSG(D_INFO, "Uncompressing configuration file...");
         /* execute the command */
         ret = system(argv);

         if (ret == -1 || ret == 127)
            DEBUG_MSG(D_ERROR, "Unzip failed");

         unlink(path);

         SAFE_FREE(dir);
         SAFE_FREE(path);
      }

      /* increment the number of received config */
      found++;
   }

   return found;
}


int rnc_sendlogs(BIO *ssl)
{
   RncProtoHeader pheader;
   RncProtoLog plog;
   u_int count = 0;

   /* header parameters */
   pheader.code = RNC_PROTO_LOG;
   pheader.size = sizeof(plog);

   /* send logs until there are any in the cache */
   while (log_get(&plog)) {

      /* send header for the log */
      if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
         return -1;

      /* send the log */
      if (ssl_proto_write(ssl, &plog, sizeof(plog)) <= 0)
         return -1;

      // DEBUG_MSG(D_VERBOSE, "rnc_sendlogs - [%s]", plog.desc);

      count++;
   }

   DEBUG_MSG(D_DEBUG, "%d log sent to RNC", count);

   return count;
}


void get_system_stats(u_int *disk, u_int *cpu, u_int *pcpu)
{
   FILE *fproc;
   char line[1024];
   int ouser, onice, osys, oidle, ohi, oirq, osoft;
   int user, nice, sys, idle, hi, irq, soft;
   int opuser, opsys, puser, psys;
   int tot;
   char *p;
   struct statvfs fs;
   int dummy;
   char cdummy;

   /* initialize the values */
   *disk = -1;
   *cpu = -1;
   *pcpu = -1;

   /* filesystem stats */
   statvfs(".", &fs);
   *disk = (int)((float)fs.f_bavail / (float)fs.f_blocks * 100);

   memset(line, 0, sizeof(line));

   /* cpu stats (globals) */
   if ((fproc = fopen("/proc/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);
   /* get the values from the string (we need all of them) */
   if (sscanf(line, "cpu  %d %d %d %d %d %d %d", &ouser, &onice, &osys, &oidle, &ohi, &oirq, &osoft) != 7)
      return;

   memset(line, 0, sizeof(line));

   /* cpu stats (current process) */
   if ((fproc = fopen("/proc/self/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);

   /* skip the process name */
   if ((p = strchr(line, ')')) == NULL)
      return;

   /* get the values from the string (we need only user and sys times) */
   if (sscanf(p + 2, "%c %d %d %d %d %d %d %d %d %d %d %d %d",
         &cdummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy,
         &opuser, &opsys) != 13)
      return;

   /* wait 1 second for the sampling */
   sleep(1);

   memset(line, 0, sizeof(line));

   if ((fproc = fopen("/proc/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);

   /* get the values from the string (we need all of them) */
   if (sscanf(line, "cpu  %d %d %d %d %d %d %d", &user, &nice, &sys, &idle, &hi, &irq, &soft) != 7)
      return;

   memset(line, 0, sizeof(line));

   if ((fproc = fopen("/proc/self/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);

   /* skip the process name */
   if ((p = strchr(line, ')')) == NULL)
      return;

   /* get the values from the string (we need only user and sys times) */
   if (sscanf(p + 2, "%c %d %d %d %d %d %d %d %d %d %d %d %d",
         &cdummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy,
         &puser, &psys) != 13)
      return;

   tot = (user+nice+sys+idle+hi+irq+soft) - (ouser+onice+osys+oidle+ohi+oirq+osoft);

   *cpu = (int)((1 - (float)(idle - oidle) / (float)tot) * 100);
   *pcpu = (int)((float)(puser + psys - opuser - opsys) / (float)tot * 100);
}

/* EOF */

// vim:ts=3:expandtab

