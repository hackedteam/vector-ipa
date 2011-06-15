
/* $Id: debug.h 790 2009-08-03 14:34:04Z alor $ */

#ifndef __DEBUG_H
#define __DEBUG_H

void debug_init(size_t cnt);
void debug_msg(char level, const char *message, ...);

#define D_EXCESSIVE 5   
#define D_VERBOSE   4   
#define D_DEBUG     3   
#define D_INFO      2
#define D_WARNING   1
#define D_ERROR     0

#define DEBUG_INIT(x) debug_init(x)
#define DEBUG_MSG(l, x, ...) debug_msg(l, x, ## __VA_ARGS__ )

#endif 

/* EOF */

// vim:ts=3:expandtab

