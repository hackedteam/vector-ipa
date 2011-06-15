/*
    MODULE -- Timer hooking module

    Copyright (C) Alberto Ornaghi

    $Id: timer.c 2995 2010-10-07 14:42:52Z alor $
*/

#include <main.h>
#include <timer.h>
#include <threads.h>

static LIST_HEAD (, timer_entry) timer_list;

struct timer_entry {
   struct timer_hook th;
   time_t last;
   LIST_ENTRY (timer_entry) next;
};

/* proto */

int add_timer(struct timer_hook *th);
int del_timer(struct timer_hook *th);
static void timer_start(void);
MY_THREAD_FUNC(timer_thread);

/*******************************************/

int add_timer(struct timer_hook *th)
{
   struct timer_entry *e;
   struct timeval tv;

   DEBUG_MSG(D_INFO, "add_timer: [%d][%p]", (u_int32)th->sec, th->func);

   /* check if the timer thread must be created */
   if (LIST_EMPTY(&timer_list))
      timer_start();

   SAFE_CALLOC(e, 1, sizeof(struct timer_entry));

   memcpy(&e->th, th, sizeof(struct timer_hook));
   gettimeofday(&tv, 0);
   e->last = tv.tv_sec;

   LIST_INSERT_HEAD(&timer_list, e, next);

   return ESUCCESS;
}

int del_timer(struct timer_hook *th)
{
   struct timer_entry *e;

   DEBUG_MSG(D_INFO, "del_timer: [%d][%p]", (u_int32)th->sec, th->func);

   LIST_FOREACH(e, &timer_list, next) {
      if (th->sec == e->th.sec && th->func == e->th.func) {
         LIST_REMOVE(e, next);
         SAFE_FREE(e);
         return ESUCCESS;
      }
   }

   return -ENOTFOUND;
}

static void timer_start(void)
{
   pthread_t pid;

   DEBUG_MSG(D_DEBUG, "timer_start");

   pid = my_thread_getpid("timer");

   if (pthread_equal(pid, MY_PTHREAD_NULL))
      my_thread_new("timer", "timer hook module", &timer_thread, NULL);
   else
      DEBUG_MSG(D_DEBUG, "timer_start: already started");
}


MY_THREAD_FUNC(timer_thread)
{
   struct timer_entry *e;
   struct timeval tv;

   /* initialize the thread */
   my_thread_init();

   DEBUG_MSG(D_DEBUG, "timer_thread: activated");

   LOOP {

      gettimeofday(&tv, 0);

      LIST_FOREACH(e, &timer_list, next) {
         /* the timer is expired (now - last) */
         if (tv.tv_sec - e->last >= e->th.sec) {
            //DEBUG_MSG(D_VERBOSE, "timer_thread: executing %p", e->th.func);
            EXECUTE(e->th.func);
            e->last = tv.tv_sec;
            //DEBUG_MSG(D_VERBOSE, "timer_thread: execution of %p terminated", e->th.func);
         }
      }

      /* sleep the minimum quantum */
      sleep(1);

      /* update the keepalive */
      GBL_STATS->keepalive = time(NULL);
      /* update the trhoughput */
      GBL_STATS->throughput = (float)GBL_STATS->bytes * 8 / 1000000;
      GBL_STATS->bytes = 0;
   }

   return NULL;
}


struct timeval timeval_subtract (struct timeval *x, struct timeval *y)
{
   struct timeval result;

   /* Perform the carry for the later subtraction by updating y. */
   if (x->tv_usec < y->tv_usec) {
      int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
      y->tv_usec -= 1000000 * nsec;
      y->tv_sec += nsec;
   }
   if (x->tv_usec - y->tv_usec > 1000000) {
      int nsec = (x->tv_usec - y->tv_usec) / 1000000;
      y->tv_usec += 1000000 * nsec;
      y->tv_sec -= nsec;
   }

   /* Compute the time remaining to wait. tv_usec is certainly positive. */
   result.tv_sec = x->tv_sec - y->tv_sec;
   result.tv_usec = x->tv_usec - y->tv_usec;

   return result;
}

/* EOF */

// vim:ts=3:expandtab

