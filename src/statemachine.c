/*
    MODULE -- Implementation of a state machine

    Copyright (C) Alberto Ornaghi 

    $Id: statemachine.c 790 2009-08-03 14:34:04Z alor $
*/

#include <main.h>
#include <statemachine.h>

/* globals */

struct state {
   u_int8 state;
   LIST_HEAD(, link) links;
   LIST_ENTRY(state) next;
};

struct link {
   u_int8 state;
   u_int8 action;
   int (*callback)(void *param);
   LIST_ENTRY(link) next;
};

/* protos */

struct sm * sm_create(void);
int sm_add_state(struct sm *sm, u_int8 state);
int sm_add_link(struct sm *sm, u_int8 s1, u_int8 s2, u_int8 action, int (*)(void *));
int sm_change_state(struct sm *sm, u_int8 s1, u_int8 s2, void *param);
int sm_send_action(struct sm *sm, u_int8 state, u_int8 action, void *param);

/*******************************************/


struct sm * sm_create(void)
{
   struct sm * sm;
   
   DEBUG_MSG(D_DEBUG, "sm_create");
   
   SAFE_CALLOC(sm, 1, sizeof(struct sm));
   
   return sm;
}

int sm_add_state(struct sm *sm, u_int8 state)
{
   struct state *s;
   
   DEBUG_MSG(D_DEBUG, "sm_add_state: %d", state);

   /* search if the state is already present or not */
   LIST_FOREACH(s, sm, next)
      if (s->state == state) {
         DEBUG_MSG(D_DEBUG, "sm_add_state: %d already present", state);
         return -EDUPLICATE;
      }

   SAFE_CALLOC(s, 1, sizeof(struct state));

   /* set the state identifier */
   s->state = state;

   LIST_INSERT_HEAD(sm, s, next);
   
   return ESUCCESS;
}

int sm_add_link(struct sm *sm, u_int8 s1, u_int8 s2, u_int8 action, int (*callback)(void *))
{
   struct state *s;
   struct link *sl;
   int found = 0;
      
   DEBUG_MSG(D_DEBUG, "sm_add_link: %d %d %p", s1, s2, callback);
   
   /* search if the states exist */ 
   LIST_FOREACH(s, sm, next)
      if (s->state == s2) {
         found = 1;
         break;
      }

   if (!found) {
      DEBUG_MSG(D_DEBUG, "sm_add_link: state %d notfound", s2);
      return -EINVALID;
   }

   found = 0;
   
   LIST_FOREACH(s, sm, next)
      if (s->state == s1) {
         found = 1;
         break;
      }
   
   if (!found) {
      DEBUG_MSG(D_DEBUG, "sm_add_link: state %d notfound", s1);
      return -EINVALID;
   }

   /* add the link to the current state (found with the second search) */
   SAFE_CALLOC(sl, 1, sizeof(struct link));

   sl->state = s2;
   sl->action = action;
   sl->callback = callback;

   LIST_INSERT_HEAD(&s->links, sl, next);
   
   return ESUCCESS;
}
     
int sm_change_state(struct sm *sm, u_int8 s1, u_int8 s2, void *param)
{
   struct state *s;
   struct link *sl;

   DEBUG_MSG(D_VERBOSE, "sm_change_state: changing from %d to %d", s1, s2);

   /* search if the start state exist */ 
   LIST_FOREACH(s, sm, next)
      if (s->state == s1) {

         /* search the arrival state */
         LIST_FOREACH(sl, &s->links, next)
            if (sl->state == s2) {
               /* execute the callback */
               if (sl->callback != NULL)
                  sl->callback(param);

               /* return the next state */
               return s2;
            }
         break;
      }

   DEBUG_MSG(D_DEBUG, "sm_change_state: NO link between %d and %d", s1, s2);

   return -ENOTFOUND;
}


int sm_send_action(struct sm *sm, u_int8 state, u_int8 action, void *param)
{
   struct state *s;
   struct link *sl;

   DEBUG_MSG(D_VERBOSE, "sm_send_action: action %d from state %d", action, state);

   /* search if the start state exist */ 
   LIST_FOREACH(s, sm, next)
      if (s->state == state) {

         /* search the arrival state */
         LIST_FOREACH(sl, &s->links, next)
            if (sl->action == action) {
               /* execute the callback */
               if (sl->callback != NULL)
                  sl->callback(param);
         
               DEBUG_MSG(D_VERBOSE, "sm_send_action: state changed to %d", sl->state);

               /* return the next state */
               return sl->state;
            }
         
         DEBUG_MSG(D_DEBUG, "sm_send_action: action %d NOT in state %d", action, state);
         break;
      }
   
   DEBUG_MSG(D_DEBUG, "sm_send_action: state %d NOT found", state);

   return -EOUTOFSTATE;
}


/* EOF */

// vim:ts=3:expandtab

