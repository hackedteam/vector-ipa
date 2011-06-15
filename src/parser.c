/*
    MODULE -- parsing utilities

    Copyright (C) Alberto Ornaghi 

    $Id: parser.c 790 2009-08-03 14:34:04Z alor $
*/

#include <main.h>
#include <conf.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

static void usage(void);
void parse_options(int argc, char **argv);

/*****************************************/

static void usage(void)
{

   fprintf(stdout, "\nUsage: %s [OPTIONS] \n", GBL_PROGRAM);

   fprintf(stdout, "\nCapture options:\n");
   fprintf(stdout, "  -r, --read <file>           read data from pcapfile <file>\n");
   
   fprintf(stdout, "\nGeneral options:\n");
   fprintf(stdout, "  -w, --watchdog              enable the watchdog for the process\n");
   fprintf(stdout, "  -S, --Siface <iface>        use this network interface to sniff\n");
   fprintf(stdout, "  -R, --Riface <iface>        use this network interface for response\n");
   fprintf(stdout, "  -a, --config <config>       use the alterative config file <config>\n");
   
   fprintf(stdout, "\nStandard options:\n");
   fprintf(stdout, "  -v, --version               prints the version and exit\n");
   fprintf(stdout, "  -h, --help                  this help screen\n");

   fprintf(stdout, "\n\n");

   clean_exit(0);
}


void parse_options(int argc, char **argv)
{
	int c;

	static struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ "watchdog", no_argument, NULL, 'w' },

		{ "iface", required_argument, NULL, 'i' },
		{ "read", required_argument, NULL, 'r' },

		{ "config", required_argument, NULL, 'a' },

		{ 0 , 0 , 0 , 0}
	};

	/* OPTIONS INITIALIZED */

	optind = 0;

	while ((c = getopt_long (argc, argv, "a:hR:S:r:vw", long_options, (int *)0)) != EOF) {

		switch (c) {

			case 'S':
				GBL_OPTIONS->Siface = strdup(optarg);
				break;
			
         case 'R':
				GBL_OPTIONS->Riface = strdup(optarg);
				break;

			case 'r':
				GBL_OPTIONS->read = 1;
				GBL_OPTIONS->pcapfile_in = strdup(optarg);
				break;

			case 'a':
				GBL_CONF->file = strdup(optarg);
				break;

			case 'h':
				usage();
				break;

			case 'w':
				GBL_OPTIONS->watchdog = 1;
				break;

			case 'v':
				printf("%s %s\n", GBL_PROGRAM, GBL_VERSION);
				clean_exit(0);
				break;

			case ':': // missing parameter
				fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
				clean_exit(-1);
				break;

			case '?': // unknown option
				fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
				clean_exit(-1);
				break;
		}
	}

	DEBUG_MSG(D_DEBUG, "parse_options: options parsed");


	/* check for other options */

	if (GBL_OPTIONS->read && GBL_PCAP->filter)
		FATAL_ERROR("Cannot read from file and set a filter on interface");

	DEBUG_MSG(D_DEBUG, "parse_options: options combination looks good");

	return;
}



/* EOF */

// vim:ts=3:expandtab

