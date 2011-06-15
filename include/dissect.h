
/* $Id: dissect.h 2546 2010-06-22 10:09:01Z alor $ */

#ifndef __DISSECT_H
#define __DISSECT_H

#include <packet.h>
#include <decode.h>

#define DISSECT_CODE(x) (u_int32)(&x)

/* exported functions */

void dissect_add(char *name, u_int8 level, u_int32 port, FUNC_DECODER_PTR(decoder));

/* return true if the packet is coming from the server */
#define FROM_SERVER(name, pack) (dissect_on_port(name, ntohs(pack->L4.src)) == ESUCCESS)

/* return true if the packet is coming from the client */
#define FROM_CLIENT(name, pack) (dissect_on_port(name, ntohs(pack->L4.dst)) == ESUCCESS)


#endif

/* EOF */

// vim:ts=3:expandtab

