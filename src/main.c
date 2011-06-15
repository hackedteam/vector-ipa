/*
 MODULE -- everything starts from this file...

 Copyright (C) Alberto Ornaghi

 $Id: main.c 2761 2010-08-02 09:09:48Z alor $
 */

#include <main.h>
#include <version.h>
#include <globals.h>
#include <signals.h>
#include <parser.h>
#include <threads.h>
#include <capture.h>
#include <ui.h>
#include <conf.h>
#include <watchdog.h>
#include <match.h>
#include <send.h>
#include <netconf.h>
#include <proxy.h>

/* protos */

void clean_exit(int errcode);
void drop_privs(void);

/*******************************************/

int main(int argc, char *argv[]) {
   /*
    * Alloc the global structures
    * We can access these structs via the macro in globals.h
    */

   globals_alloc();

   /* start with the maximum log level */
   GBL_CONF->log_level = 3;

   /* set up the global variables */
   GBL_PROGRAM = strdup(basename(argv[0]));
   GBL_VERSION = strdup(VERSION);
   GBL_RCS_VERSION = strdup(RCS_VER);

   /* init the debug */
   DEBUG_INIT(GBL_ENV->crash);
   DEBUG_MSG(D_INFO, "main -- here we go !!");

   /* register the main thread as "init" */
   my_thread_register(MY_PTHREAD_SELF, "init", "initialization phase");

   /* activate the signal handler */
   signal_handler();

   /* getopt related parsing...  */
   parse_options(argc, argv);

   /*
    * setup the watchdog.
    * the process forks here and the parent does nothing but
    * checking if the son is alive. when it receives a SIGCHLD,
    * it forks again and the process restarts. the real
    * job is always performed by the son.
    */
   watchdog_init();

   /*
    * start the normal activity...
    * this is the entry point after the detection of a crash
    * make sure to reinitialize the thread and the signal handler.
    */

   /* register the main thread as "init" */
   my_thread_register(MY_PTHREAD_SELF, "init", "initialization phase");

   /* activate the signal handler */
   signal_handler();

   /* init random numbers */
   srandom(time(NULL));

   /* save the starting time */
   GBL_STATS->uptime = time(NULL);

   /* load the configuration file */
   load_conf();

   /* get the list of available interfaces */
   capture_getifs();

   DEBUG_MSG(D_INFO, "RCSRedirect : activated!");
   my_thread_register(MY_PTHREAD_SELF, "redirector", "initialization phase");

   /* initialize libnet */
   send_init();

   /* initialize libpcap */
   capture_init();

   /* load the rules file */
   load_rules();

   /**** INITIALIZATION PHASE TERMINATED ****/

   /* we need the protocol stack analyzer */
   GBL_OPTIONS->analyze = 1;

   /* set up the filters */
   match_fqdn_init();
   match_url_init();
   match_users_init();

   /* start the proxy module */
   proxy_start();

   /* log the status */
   log_add(RNC_LOG_INFO, "RCSRedirector starting...");

   /* start the communication module */
   netconf_start();

   /* start the sniffing loop */
   capture_start();

   /* NOT REACHED IN LIVE CAPTURE */

   clean_exit(0);

   return 0;
}

/*
 * cleanly exit from the program
 */

void clean_exit(int errcode) {
   DEBUG_MSG(D_INFO, "clean_exit: %d", errcode);

   /* kill all the running threads but the current */
   my_thread_kill_all();

   /* call all the ATEXIT functions */
   exit(errcode);
}

/* EOF */

// vim:ts=3:expandtab

