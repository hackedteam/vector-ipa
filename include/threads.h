
/* $Id: threads.h 790 2009-08-03 14:34:04Z alor $ */

#ifndef __THREADS_H
#define __THREADS_H

#include <stdint.h>
#include <pthread.h>

struct my_thread {
   char *name;
   char *description;
   pthread_t id;
};

/* a value to be used to return errors in fuctcions using pthread_t values */
pthread_t MY_PTHREAD_NULL;
#define MY_PTHREAD_SELF MY_PTHREAD_NULL
#define PTHREAD_ID(id)  (*(unsigned long*)&(id)) 

#define MY_THREAD_FUNC(x) void * x(void *args)
#define MY_THREAD_PARAM  args

char * my_thread_getname(pthread_t id);
pthread_t my_thread_getpid(char *name);
char * my_thread_getdesc(pthread_t id);
void my_thread_register(pthread_t id, char *name, char *desc);
pthread_t my_thread_new(char *name, char *desc, void *(*function)(void *), void *args);
void my_thread_destroy(pthread_t id);
void my_thread_init(void);
void my_thread_kill_all(void);
void my_thread_exit(void);

#define CANCELLATION_POINT()  pthread_testcancel()

#endif

/* EOF */

// vim:ts=3:expandtab

