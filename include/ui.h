
/* $Id: ui.h 790 2009-08-03 14:34:04Z alor $ */

#ifndef __UI_H
#define __UI_H

#include <stdarg.h>

void ui_msg(const char *fmt, ...);
void ui_error(const char *fmt, ...);
void ui_fatal_error(const char *msg);
void ui_stats(void);

#define USER_MSG(x, ...) ui_msg(x, ## __VA_ARGS__ )

#define FATAL_MSG(x, ...) do { ui_error(x, ## __VA_ARGS__ ); return (-EFATAL); } while(0)

#endif

/* EOF */

// vim:ts=3:expandtab

