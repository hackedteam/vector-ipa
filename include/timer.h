
/* $Id: timer.h 2995 2010-10-07 14:42:52Z alor $ */

#ifndef __TIMER_H
#define __TIMER_H

struct timer_hook {
   time_t sec;
   void (*func)(void);
};


/* exported functions */

extern int add_timer(struct timer_hook *th);
extern int del_timer(struct timer_hook *th);

extern struct timeval timeval_subtract (struct timeval *x, struct timeval *y);

#endif

/* EOF */

// vim:ts=3:expandtab

