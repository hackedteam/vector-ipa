/*
    MODULE -- thread handling

    Copyright (C) Alberto Ornaghi

    $Id: threads.c 3009 2010-10-18 12:44:40Z alor $
*/

#include <main.h>
#include <threads.h>

#include <pthread.h>

struct thread_list {
   struct my_thread t;
   LIST_ENTRY (thread_list) next;
};


/* global data */

static LIST_HEAD(, thread_list) thread_list_head;

static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;
#define THREADS_LOCK     do{ pthread_mutex_lock(&threads_mutex); } while(0)
#define THREADS_UNLOCK   do{ pthread_mutex_unlock(&threads_mutex); } while(0)

static pthread_mutex_t init_mtx = PTHREAD_MUTEX_INITIALIZER;
#define INIT_LOCK     do{ DEBUG_MSG(D_VERBOSE, "thread_init_lock"); pthread_mutex_lock(&init_mtx); } while(0)
#define INIT_UNLOCK   do{ DEBUG_MSG(D_VERBOSE, "thread_init_unlock"); pthread_mutex_unlock(&init_mtx); } while(0)

#if defined(OS_DARWIN) || defined(OS_WINDOWS) || defined(OS_CYGWIN)
   /* darwin and windows are broken, pthread_join hangs up forever */
   #define BROKEN_PTHREAD_JOIN
#endif

/* protos... */

char * my_thread_getname(pthread_t id);
pthread_t my_thread_getpid(char *name);
char * my_thread_getdesc(pthread_t id);
void my_thread_register(pthread_t id, char *name, char *desc);
pthread_t my_thread_new(char *name, char *desc, void *(*function)(void *), void *args);
void my_thread_destroy(pthread_t id);
void my_thread_init(void);
void my_thread_kill_all(void);
void my_thread_exit(void);

/*******************************************/

/* returns the name of a thread */

char * my_thread_getname(pthread_t id)
{
   struct thread_list *current;
   char *name;

   if (pthread_equal(id, MY_PTHREAD_SELF))
      id = pthread_self();

   /* don't lock here to avoid deadlock in debug messages */

   LIST_FOREACH(current, &thread_list_head, next) {
      if (pthread_equal(current->t.id, id)) {
         name = current->t.name;
         return name;
      }
   }

   return "NR_THREAD";
}

/*
 * returns the pid of a thread
 * ZERO if not found !! (take care, not -ENOTFOUND !)
 */

pthread_t my_thread_getpid(char *name)
{
   struct thread_list *current;
   pthread_t pid;

   /* if no name is provided, return itself */
   if (name == NULL) {
      return pthread_self();
   }

   THREADS_LOCK;

   LIST_FOREACH(current, &thread_list_head, next) {
      if (!strcasecmp(current->t.name,name)) {
         pid = current->t.id;
         THREADS_UNLOCK;
         return pid;
      }
   }

   THREADS_UNLOCK;

   return MY_PTHREAD_NULL;
}

/* returns the description of a thread */

char * my_thread_getdesc(pthread_t id)
{
   struct thread_list *current;
   char *desc;

   if (pthread_equal(id, MY_PTHREAD_SELF))
      id = pthread_self();

   THREADS_LOCK;

   LIST_FOREACH(current, &thread_list_head, next) {
      if (pthread_equal(current->t.id, id)) {
         desc = current->t.description;
         THREADS_UNLOCK;
         return desc;
      }
   }

   THREADS_UNLOCK;

   return "";
}


/* add a thread in the thread list */

void my_thread_register(pthread_t id, char *name, char *desc)
{
   struct thread_list *current, *newelem;

   if (pthread_equal(id, MY_PTHREAD_SELF))
      id = pthread_self();

   DEBUG_MSG(D_VERBOSE, "my_thread_register -- [%08X] %s", PTHREAD_ID(id), name);

   SAFE_CALLOC(newelem, 1, sizeof(struct thread_list));

   newelem->t.id = id;
   newelem->t.name = strdup(name);
   newelem->t.description = strdup(desc);

   THREADS_LOCK;

   LIST_FOREACH(current, &thread_list_head, next) {
      if (pthread_equal(current->t.id, id)) {
         SAFE_FREE(current->t.name);
         SAFE_FREE(current->t.description);
         LIST_REPLACE(current, newelem, next);
         SAFE_FREE(current);
         THREADS_UNLOCK;
         return;
      }
   }

   LIST_INSERT_HEAD(&thread_list_head, newelem, next);

   THREADS_UNLOCK;

}

/*
 * creates a new thread on the given function
 */

pthread_t my_thread_new(char *name, char *desc, void *(*function)(void *), void *args)
{
   pthread_t id;

   DEBUG_MSG(D_INFO, "my_thread_new -- [%s]", name);

   /*
    * lock the mutex to syncronize with the new thread.
    * the newly created thread will perform INIT_UNLOCK
    * so at the end of this function we are sure that the
    * thread had be initialized
    */
   INIT_LOCK;

   if (pthread_create(&id, NULL, function, args) != 0)
      ERROR_MSG("not enough resources to create a new thread in this process");

   my_thread_register(id, name, desc);

   DEBUG_MSG(D_VERBOSE, "my_thread_new -- %08X created ", PTHREAD_ID(id));

   /* the new thread will unlock this */
   INIT_LOCK;
   INIT_UNLOCK;

   return id;
}

/*
 * set the state of a thread
 * all the new thread MUST call this on startup
 */
void my_thread_init(void)
{
   pthread_t id = pthread_self();

   DEBUG_MSG(D_VERBOSE, "my_thread_init -- %08X", PTHREAD_ID(id));

   /*
    * allow a thread to be cancelled as soon as the
    * cancellation  request  is received
    */
   pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
   pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

   /* sync with the creator */
   INIT_UNLOCK;

   DEBUG_MSG(D_INFO, "my_thread_init -- [%s][%08X] ready and syncronized", my_thread_getname(id), PTHREAD_ID(id));
}


/*
 * destroy a thread in the list
 */
void my_thread_destroy(pthread_t id)
{
   struct thread_list *current;

   if (pthread_equal(id, MY_PTHREAD_SELF))
      id = pthread_self();

   DEBUG_MSG(D_INFO, "my_thread_destroy -- terminating [%s][%08X]", my_thread_getname(id), PTHREAD_ID(id));

   /* send the cancel signal to the thread */
   pthread_cancel((pthread_t)id);

#ifndef BROKEN_PTHREAD_JOIN
   DEBUG_MSG(D_DEBUG, "my_thread_destroy: pthread_join");
   /* wait until it has finished */
   pthread_join((pthread_t)id, NULL);
#endif

   DEBUG_MSG(D_INFO, "my_thread_destroy -- [%s] terminated", my_thread_getname(id));

   THREADS_LOCK;

   LIST_FOREACH(current, &thread_list_head, next) {
      if (pthread_equal(current->t.id, id)) {
         SAFE_FREE(current->t.name);
         SAFE_FREE(current->t.description);
         LIST_REMOVE(current, next);
         SAFE_FREE(current);
         THREADS_UNLOCK;
         return;
      }
   }

   THREADS_UNLOCK;

}


/*
 * kill all the registerd thread but
 * the calling one
 */

void my_thread_kill_all(void)
{
   struct thread_list *current, *old;
   pthread_t id = pthread_self();

   DEBUG_MSG(D_DEBUG, "my_thread_kill_all -- caller [%s][%08X]", my_thread_getname(id), PTHREAD_ID(id));

   THREADS_LOCK;

   LIST_FOREACH_SAFE(current, &thread_list_head, next, old) {
      /* skip ourself */
      if (!pthread_equal(current->t.id, id)) {
         DEBUG_MSG(D_INFO, "my_thread_kill_all -- terminating [%s][%08X]", current->t.name, PTHREAD_ID(current->t.id));

         /* send the cancel signal to the thread */
         pthread_cancel((pthread_t)current->t.id);

#ifndef BROKEN_PTHREAD_JOIN
         DEBUG_MSG(D_DEBUG, "my_thread_destroy: pthread_join");
         /* wait until it has finished */
         pthread_join(current->t.id, NULL);
#endif

         DEBUG_MSG(D_INFO, "my_thread_kill_all -- [%s] terminated", current->t.name);

         SAFE_FREE(current->t.name);
         SAFE_FREE(current->t.description);
         LIST_REMOVE(current, next);
         SAFE_FREE(current);
      }
   }

   THREADS_UNLOCK;
}

/*
 * used by a thread that wants to terminate itself
 */
void my_thread_exit(void)
{
   struct thread_list *current, *old;
   pthread_t id = pthread_self();

   DEBUG_MSG(D_INFO, "my_thread_exit -- caller [%s][%08X]", my_thread_getname(id), PTHREAD_ID(id));

   THREADS_LOCK;

   LIST_FOREACH_SAFE(current, &thread_list_head, next, old) {
      /* delete our entry */
      if (pthread_equal(current->t.id, id)) {
         SAFE_FREE(current->t.name);
         SAFE_FREE(current->t.description);
         LIST_REMOVE(current, next);
         SAFE_FREE(current);
      }
   }

   THREADS_UNLOCK;

   /* perform a clean exit of the thread */
   pthread_exit(0);

}

/* EOF */

// vim:ts=3:expandtab

