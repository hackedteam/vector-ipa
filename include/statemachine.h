
/* $Id: statemachine.h 790 2009-08-03 14:34:04Z alor $ */

#ifndef __STATEMACHINE_H
#define __STATEMACHINE_H

LIST_HEAD(sm, state);

struct sm * sm_create(void);
int sm_add_state(struct sm *sm, u_int8 state);
int sm_add_link(struct sm *sm, u_int8 s1, u_int8 s2, u_int8 action, int (*)(void *));
int sm_change_state(struct sm *sm, u_int8 s1, u_int8 s2, void *param);
int sm_send_action(struct sm *sm, u_int8 state, u_int8 action, void *param);


#endif

/* EOF */

// vim:ts=3:expandtab

