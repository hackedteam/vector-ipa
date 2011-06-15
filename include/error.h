
/* $Id: error.h 790 2009-08-03 14:34:04Z alor $ */

#ifndef __ERROR_H
#define __ERROR_H

#include <errno.h>

/* 
 * the following error codes are to be returned as negative values
 * except for ESUCCESS.
 */
enum {
   ESUCCESS    = 0,
   ENOTFOUND   = 1,
   EINIT       = 2,
   ENOTHANDLED = 3,
   EINVALID    = 4,
   ENOADDRESS  = 5,
   EDUPLICATE  = 6,
   ETIMEOUT    = 7,
   EOUTOFSTATE = 8,
   EFAILURE    = 9,
	ETHREADEXIT = 10,  // use in threads when function ret values requires thread loop exit
   EVERSION    = 254,
   EFATAL      = 255,
};

void error_msg(char *file, const char *function, int line, char *message, ...);
void fatal_error(char *message, ...);
void bug(char *file, const char *function, int line, char *message);

#define ERROR_MSG(x, ...) error_msg(__FILE__, __FUNCTION__, __LINE__, x, ## __VA_ARGS__ )

#define FATAL_ERROR(x, ...) do { fatal_error(x, ## __VA_ARGS__ ); } while(0)

#define ON_ERROR(x, y, fmt, ...) do { if (x == y) ERROR_MSG(fmt, ## __VA_ARGS__ ); } while(0)

#define BUG_IF(x) do { if (x) bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)

#define BUG(x) do { bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)

#define NOT_IMPLEMENTED() do { BUG("Not yet implemented, please contact the authors"); } while(0)


#endif

/* EOF */

// vim:ts=3:expandtab

