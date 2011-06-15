/*
    MODULE -- user interface stuff

    Copyright (C) Alberto Ornaghi 

    $Id: ui.c 790 2009-08-03 14:34:04Z alor $
*/

#include <main.h>
#include <ui.h>

#include <stdarg.h>
#include <pthread.h>

/* protos... */

void ui_msg(const char *fmt, ...);
void ui_error(const char *fmt, ...);
void ui_fatal_error(const char *msg);

/*******************************************/

/*
 * the FATAL_MSG error handling function
 */
void ui_error(const char *fmt, ...)
{
   va_list ap;
   int n;
   size_t size = 50;
   char *msg;

   /* 
    * we hope the message is shorter
    * than 'size', else realloc it
    */
    
   SAFE_CALLOC(msg, size, sizeof(char));

   while (1) {
      /* Try to print in the allocated space. */
      va_start(ap, fmt);
      n = vsnprintf (msg, size, fmt, ap);
      va_end(ap);
      
      /* If that worked, we have finished. */
      if (n > -1 && (size_t)n < size)
         break;
   
      /* Else try again with more space. */
      if (n > -1)    /* glibc 2.1 */
         size = n+1; /* precisely what is needed */
      else           /* glibc 2.0 */
         size *= 2;  /* twice the old size */
      
      SAFE_REALLOC(msg, size);
   }

   /* dump the error in the debug file */
   DEBUG_MSG(D_ERROR, "%s", msg);
   
   /* call the function */
   fprintf(stderr, "\n%s\n", msg);
   
   /* free the message */
   SAFE_FREE(msg);
}


/*
 * the FATAL_ERROR error handling function
 */
void ui_fatal_error(const char *msg)
{
   /* 
    * call the function 
    */
   fprintf(stderr, "\n%s\n\n", msg);
   exit(-1);
   
}


/*
 * this fuction enqueues the messages displayed by
 * ui_msg_flush()
 */

void ui_msg(const char *fmt, ...)
{
   va_list ap;
   char *msg;
   int n;
   size_t size = 50;

   /* 
    * we hope the message is shorter
    * than 'size', else realloc it
    */
    
   SAFE_CALLOC(msg, size, sizeof(char));

   while (1) {
      /* Try to print in the allocated space. */
      va_start(ap, fmt);
      n = vsnprintf (msg, size, fmt, ap);
      va_end(ap);
      
      /* If that worked, we have finished. */
      if (n > -1 && (size_t)n < size)
         break;
   
      /* Else try again with more space. */
      if (n > -1)    /* glibc 2.1 */
         size = n+1; /* precisely what is needed */
      else           /* glibc 2.0 */
         size *= 2;  /* twice the old size */
      
      SAFE_REALLOC(msg, size);
   }

   /* save the message in the log */
   DEBUG_MSG(D_INFO, "%s", msg);
   
   /* print the message */
   if (!GBL_OPTIONS->watchdog) {
      fprintf(stdout, "%s", msg);
      fflush(stdout);
   }

   SAFE_FREE(msg);
}


/* EOF */

// vim:ts=3:expandtab

