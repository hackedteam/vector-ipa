/*
    MODULE -- BIO injector module (inject data after a search point)

    Copyright (C) Alberto Ornaghi

    $Id: bio_injector.c 3033 2010-10-25 13:49:37Z alor $
*/

#include <main.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <bio_injector.h>

/* globals */

#define BIO_TYPE_INJECT_FILTER (98|0x200)

struct injector_obj {
   /* internal buffer */
   char *buf;
   int bsize;
   int curr;
   /* injection part */
   char *search;
   char *inject;
   int isize;
   int injected;
};

/* protos */

void *injector_new(void);
void injector_free(void *);
int injector_feed(void *, const char *, int);
int injector_eat(void *, char **, int *);

static int inject_write(BIO *h, const char *buf, int num);
static int inject_read(BIO *h, char *buf, int size);
static int inject_puts(BIO *h, const char *str);
static int inject_gets(BIO *h, char *str, int size);
static long inject_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int inject_new(BIO *h);
static int inject_free(BIO *data);
static long inject_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

BIO_METHOD* BIO_f_inject(void);

BIO_METHOD method_inject =
{
   BIO_TYPE_INJECT_FILTER,
   "RCS Inject filter",
   inject_write,
   inject_read,
   inject_puts,
   inject_gets,
   inject_ctrl,
   inject_new,
   inject_free,
   inject_callback_ctrl,
};
/************************************************/

void *injector_new(void)
{
   struct injector_obj *inj;

   SAFE_CALLOC(inj, sizeof(struct injector_obj), 1);

   return inj;
}

void injector_free(void *self)
{
   struct injector_obj *inj = (struct injector_obj *)self;

   /* sanity check */
   if (self == NULL)
      return;

   SAFE_FREE(inj->search);
   SAFE_FREE(inj->inject);
   SAFE_FREE(inj->buf);
   SAFE_FREE(self);
}

int injector_feed(void *self, const char *in, int inl)
{
   struct injector_obj *inj = (struct injector_obj *)self;
   char *inject_ptr = NULL;

   /* sanity check */
   if (self == NULL)
      return 0;

   /* append the data to the buffer */
   SAFE_REALLOC(inj->buf, inj->bsize + inl);
   memcpy(inj->buf + inj->bsize, in, inl);
   inj->bsize += inl;

   /* sanity check */
   if (inj->search == NULL || inj->inject == NULL) {
      DEBUG_MSG(D_ERROR, "injector_feed: cannot search for NULL");
      return inj->bsize;
   }

   /*
    * check if it is the right place to inject
    * check after the append to prevent cross-boundary search failures
    */
   if (inj->injected == 0 && (inject_ptr = strcasestr(inj->buf, inj->search)) != NULL) {
      /* remember that we have already injected */
      inj->injected = 1;

      /* move at the end of the search pattern */
      inject_ptr += strlen(inj->search);

      DEBUG_MSG(D_INFO, "Injecting %d bytes into stream...", inj->isize);

      /* make room for the inject buffer */
      SAFE_REALLOC(inj->buf, inj->bsize + inj->isize);

      /* move the original buffer after the injected section */
      memmove(inject_ptr + inj->isize, inject_ptr, inj->bsize - (inject_ptr - inj->buf));

      /* inject the "inject buffer" */
      memcpy(inject_ptr, inj->inject, inj->isize);

      /* update the new size of the buffer */
      inj->bsize += inj->isize;
   }

   return inj->bsize;
}

int injector_eat(void *self, char **out, int *outl)
{
   struct injector_obj *inj = (struct injector_obj *)self;

   /* sanity check */
   if (self == NULL)
      return 0;

   /* pass the pointer and size to the caller */
   *out = inj->buf + inj->curr;
   *outl = inj->bsize - inj->curr;

   /* update the current internal pointer */
   inj->curr = inj->bsize;

   if (inj->injected == 1) {
      DEBUG_MSG(D_INFO, "Injection completed");
      /* prevent this message to appear twice */
      inj->injected = 2;
   }

   return *outl;
}


BIO_METHOD* BIO_f_inject(void)
{
   return (&method_inject);
}

static int inject_new(BIO *b)
{
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   b->ptr = injector_new();
   b->init = 1;
   b->flags = 0;

   return (1);
}

static int inject_free(BIO *b)
{
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (b == NULL)
      return (0);

   injector_free(b->ptr);

   return (1);
}

static int inject_read(BIO *b, char *out, int outl)
{
   DEBUG_MSG(D_EXCESSIVE, "%s: %d bytes", __FUNCTION__, outl);

   int ret = 0;

   if (out == NULL)
      return (0);

   if (b->next_bio == NULL)
      return (0);

   /* read from the next BIO */
   ret = BIO_read(b->next_bio, out, outl);

   BIO_clear_retry_flags(b);
   BIO_copy_next_retry(b);

   return(ret);
}

static int inject_write(BIO *b, const char *in, int inl)
{
   char *out;
   int outl;

   DEBUG_MSG(D_EXCESSIVE, "%s: %d bytes", __FUNCTION__, inl);

   int ret = 0;

   if ( (in == NULL) || (inl == 0) )
      return 0;

   if (b->next_bio == NULL || b->ptr == NULL)
      return 0;

   /* feed the injector which will modify the input as needed */
   injector_feed(b->ptr, in, inl);

   /* if the injector has some bytes for us, take them and push to the next bio */
   if (injector_eat(b->ptr, &out, &outl)) {
      /* send data to the next BIO */
      ret = BIO_write(b->next_bio, out, outl);
   }

   BIO_clear_retry_flags(b);
   BIO_copy_next_retry(b);

   return ret;
}

static long inject_ctrl(BIO *b, int cmd, long num, void *ptr)
{
   long ret;

   //DEBUG_MSG(D_DEBUG, "%s: %d", __FUNCTION__, cmd);

   /* my case */
   switch(cmd) {
      case BIO_C_SET_BUF_MEM:
      {
         struct bio_inject_setup *bis = (struct bio_inject_setup *)ptr;
         struct injector_obj *inj = (struct injector_obj *)b->ptr;

         /* prevent missing pointer if called twice */
         SAFE_FREE(inj->search);
         SAFE_FREE(inj->inject);

         inj->search = strdup(bis->search);
         inj->inject = strdup(bis->inject);
         inj->isize = bis->inject_len;
         return 1;
      }
      break;
      case BIO_C_GET_BUF_MEM_PTR:
      {
         struct bio_inject_setup *bis = (struct bio_inject_setup *)ptr;
         struct injector_obj *inj = (struct injector_obj *)b->ptr;

         bis->search = inj->search;
         bis->inject = inj->inject;
         bis->inject_len = inj->isize;
         return 1;
      }
      break;

   }

   if (b->next_bio == NULL)
      return 0;

   /* default stuff */
   switch(cmd) {
      case BIO_C_DO_STATE_MACHINE:
         BIO_clear_retry_flags(b);
         ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
         BIO_copy_next_retry(b);
         break;

      case BIO_CTRL_FLUSH:
         ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
         break;

      case BIO_CTRL_DUP:
         ret = 0L;
         break;

      default:
         ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
         break;
   }

   return(ret);
}

static long inject_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (b->next_bio == NULL)
      return(0);

   return( BIO_callback_ctrl(b->next_bio, cmd, fp) );
}

static int inject_gets(BIO *bp, char *buf, int size)
{
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (bp->next_bio == NULL)
      return(0);

   return ( BIO_gets(bp->next_bio, buf, size) );
}

static int inject_puts(BIO *bp, const char *str)
{
   //DEBUG_MSG(D_DEBUG, "%s", __FUNCTION__);

   if (bp->next_bio == NULL)
      return(0);

   return( BIO_puts(bp->next_bio,str) );
}


/* EOF */

// vim:ts=3:expandtab

