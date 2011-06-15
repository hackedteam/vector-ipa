
/* $Id: socket.h 790 2009-08-03 14:34:04Z alor $ */

#ifndef __SOCKET_H
#define __SOCKET_H

/* The never ending errno problems... */
#define GET_SOCK_ERRNO()  errno

int open_tcp_socket_connect(const char *host, u_int16 port);
int open_udp_socket_connect(const char *host, u_int16 port);
int open_tcp_socket_accept(u_int16 port);
int open_udp_socket_accept(u_int16 port);
int socket_accept(int s);
int socket_close(int s);
void set_blocking(int s, int set);
int socket_send(int s, const u_char *payload, size_t size);
int socket_recv(int s, u_char *payload, size_t size);

#endif

/* EOF */

// vim:ts=3:expandtab

