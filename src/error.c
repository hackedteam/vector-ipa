/*
    MODULE -- error handling module

    Copyright (C) Alberto Ornaghi

    $Id: error.c 2777 2010-08-25 11:54:03Z alor $
*/

#include <main.h>
#include <ui.h>

#include <stdarg.h>
#include <errno.h>

#define ERROR_MSG_LEN 200

void error_msg(char *file, const char *function, int line, char *message, ...);
void fatal_error_msg(char *message, ...);
void bug(char *file, const char *function, int line, char *message);

/*******************************************/

/*
 * raise an error
 */
void error_msg(char *file, const char *function, int line, char *message, ...)
{
   va_list ap;
   char errmsg[ERROR_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(errmsg, ERROR_MSG_LEN, message, ap);
   va_end(ap);

   DEBUG_MSG(D_ERROR, "ERROR : %d, %s | %s [%s:%s:%d]",  errno, strerror(errno), errmsg, file, function, line);

   fprintf(stderr, "ERROR : %d, %s\n[%s:%s:%d]\n\n %s \n\n",  errno, strerror(errno), file, function, line, errmsg);

   exit(-errno);
}


/*
 * raise a fatal error
 */
void fatal_error(char *message, ...)
{
   va_list ap;
   char errmsg[ERROR_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(errmsg, ERROR_MSG_LEN, message, ap);
   va_end(ap);

   /* if debug was initialized... */
   DEBUG_MSG(D_ERROR, "FATAL: %s", errmsg);

   /* invoke the ui method */
   ui_fatal_error(errmsg);

   /* the ui should exits, but to be sure... */
   exit(-1);
}

/*
 * used in sanity check
 * it represent a BUG in the software
 */

void bug(char *file, const char *function, int line, char *message)
{
   DEBUG_MSG(D_ERROR, "BUG : [%s:%s:%d] %s \n", file, function, line, message );

   fprintf(stderr, "\n\nBUG at [%s:%s:%d]\n\n %s \n\n", file, function, line, message );

   exit(-666);
}


/* EOF */

// vim:ts=3:expandtab

