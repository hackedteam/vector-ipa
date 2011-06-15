/*
    MODULE -- socket handling module

    Copyright (C) Alberto Ornaghi 

    $Id: socket.c 790 2009-08-03 14:34:04Z alor $
*/

#include <main.h>
#include <signals.h>
#include <poll.h>
#include <socket.h>

#include <netdb.h>                                                                               
#include <sys/socket.h>                                                                          
#include <netinet/in.h>                                                                          
#include <arpa/inet.h>

#include <fcntl.h>

/* protos */

int open_tcp_socket_connect(const char *host, u_int16 port);
int open_udp_socket_connect(const char *host, u_int16 port);
int open_tcp_socket_accept(u_int16 port);
int open_udp_socket_accept(u_int16 port);
int socket_accept(int s);
int socket_close(int s);
void set_blocking(int s, int set);
int socket_send(int s, const u_char *payload, size_t size);
int socket_recv(int s, u_char *payload, size_t size);

/*******************************************/

/* 
 * set or unset blocking flag on a socket
 */
void set_blocking(int s, int set)
{
   int ret;

   /* get the current flags */
   if ((ret = fcntl(s, F_GETFL, 0)) == -1)
      return;
   
   if (set) 
      ret &= ~O_NONBLOCK;
   else
      ret |= O_NONBLOCK;
   
   /* set the flag */
   fcntl (s, F_SETFL, ret);
}


/*
 * open a tcp socket to the specified host and port
 */
int open_tcp_socket_connect(const char *host, u_int16 port)
{
   struct hostent *infh;
   struct sockaddr_in sa_in;
   int sh, ret, err = 0;
#define TSLEEP (50*1000) /* 50 milliseconds */
   int loops = (/* TIMEOUT */5 * 10e5) / TSLEEP;

   DEBUG_MSG(D_INFO, "open_tcp_socket_connect -- [%s]:[%d]", host, port);

   /* prepare the structures */
   memset((char*)&sa_in, 0, sizeof(sa_in));
   sa_in.sin_family = AF_INET;
   sa_in.sin_port = htons(port);

   /* resolve the hostname */
   if ( (infh = gethostbyname(host)) != NULL )
      memcpy(&sa_in.sin_addr, infh->h_addr, infh->h_length);
   else {
      if ( inet_aton(host, (struct in_addr *)&sa_in.sin_addr.s_addr) == 0 )
         return -ENOADDRESS;
   }

   /* open the socket */
   if ( (sh = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      return -EFATAL;
 
   /* set nonblocking socket */
   set_blocking(sh, 0);
  
   do {
      /* connect to the server */
      ret = connect(sh, (struct sockaddr *)&sa_in, sizeof(sa_in));
      
      /* connect is in progress... */
      if (ret < 0) {
         err = GET_SOCK_ERRNO();
         if (err == EINPROGRESS || err == EALREADY || err == EWOULDBLOCK || err == EAGAIN) {
            /* sleep a quirk of time... */
            usleep(TSLEEP);
         }
      } else { 
         /* there was an error or the connect was successful */
         break;
      }
   } while(loops--);
 
   /* 
    * we cannot recall get_sock_errno because under windows
    * calling it twice would not return the same result
    */
   err = ret < 0 ? err : 0;
   
   /* reached the timeout */
   if (ret < 0 && (err == EINPROGRESS || err == EALREADY || err == EAGAIN)) {
      DEBUG_MSG(D_ERROR, "open_tcp_socket_connect: connect() timeout: %d", err);
      socket_close(sh);
      return -ETIMEOUT;
   }

   /* error while connecting */
   if (ret < 0 && err != EISCONN) {
      DEBUG_MSG(D_ERROR, "open_tcp_socket_connect: connect() error: %d", err);
      socket_close(sh);
      return -EINVALID;
   }
      
   DEBUG_MSG(D_DEBUG, "open_tcp_socket_connect: connect() connected.");
   
   /* reset the state to blocking socket */
   set_blocking(sh, 1);
   
   
   DEBUG_MSG(D_DEBUG, "open_tcp_socket_connect: %d", sh);
   
   return sh;
}

/*
 * open an udp socket to the specified host and port
 */
int open_udp_socket_connect(const char *host, u_int16 port)
{
   struct hostent *infh;
   struct sockaddr_in sa_in;
   int sh;

   DEBUG_MSG(D_INFO, "open_udp_socket_connect -- [%s]:[%d]", host, port);

   /* prepare the structures */
   memset((char*)&sa_in, 0, sizeof(sa_in));
   sa_in.sin_family = AF_INET;
   sa_in.sin_port = htons(port);

   /* resolve the hostname */
   if ( (infh = gethostbyname(host)) != NULL )
      memcpy(&sa_in.sin_addr, infh->h_addr, infh->h_length);
   else {
      if ( inet_aton(host, (struct in_addr *)&sa_in.sin_addr.s_addr) == 0 )
         return -ENOADDRESS;
   }

   /* open the socket */
   if ( (sh = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      return -EFATAL;
   
   /* connect the socket */
   connect(sh, (struct sockaddr *)&sa_in, sizeof(sa_in));
 
   DEBUG_MSG(D_DEBUG, "open_udp_socket_connect: %d", sh);
   
   return sh;
}


/*
 * open a listening socket on the specified port
 */
int open_tcp_socket_accept(u_int16 port)
{
   struct sockaddr_in sa_in;
   int sh, opt;

   DEBUG_MSG(D_DEBUG, "open_tcp_socket_accept -- [%d]", port);

   /* prepare the structures */
   memset((char*)&sa_in, 0, sizeof(sa_in));
   sa_in.sin_family = AF_INET;
   sa_in.sin_port = htons(port);
   sa_in.sin_addr.s_addr = INADDR_ANY;

   /* open the socket */
   if ( (sh = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      return -EFATAL;

   /* to avoid "address already in use" error :) */
   opt = 1;
   if (setsockopt (sh, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt)) < 0)
      return -EFATAL;
 
   /* bind it */
   if ( bind (sh, (struct sockaddr *) &sa_in, sizeof(sa_in)) < 0) {
      DEBUG_MSG(D_ERROR, "open_tcp_socket_accept: %s", strerror(errno));
      close(sh);
      return -EFATAL;
   }

   /* max pending requests */ 
   listen(sh, 4);
   
   DEBUG_MSG(D_DEBUG, "open_tcp_socket_accept: %d", sh);
   
   return sh;
}

/*
 * open a listening UDP socket on the specified port
 */
int open_udp_socket_accept(u_int16 port)
{
   struct sockaddr_in sa_in;
   int sh;

   DEBUG_MSG(D_INFO, "open_udp_socket_accept -- [%d]", port);

   /* prepare the structures */
   memset((char*)&sa_in, 0, sizeof(sa_in));
   sa_in.sin_family = AF_INET;
   sa_in.sin_port = htons(port);
   sa_in.sin_addr.s_addr = INADDR_ANY;

   /* open the socket */
   if ( (sh = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      return -EFATAL;
 
   /* bind it */
   if ( bind (sh, (struct sockaddr *) &sa_in, sizeof(sa_in)) < 0) {
      DEBUG_MSG(D_ERROR, "open_udp_socket_accept: %s", strerror(errno));
      close(sh);
      return -EFATAL;
   }

   DEBUG_MSG(D_DEBUG, "open_udp_socket_accept: %d", sh);
   
   return sh;
}

/* 
 * accept a connection on that socket
 */
int socket_accept(int s)
{
   int afd;
   
   DEBUG_MSG(D_DEBUG, "socket_accept: %d", s);

   if ( (afd = accept(s, NULL, NULL)) < 0) {
      DEBUG_MSG(D_ERROR, "socket_accept: %s", strerror(errno));
      return -EFATAL;
   }
   
   return afd;
}

/*
 * close the given socket 
 */
int socket_close(int s)
{
   DEBUG_MSG(D_DEBUG, "socket_close: %d", s);

   /* close the socket */
   return close(s);
}


/* 
 * send a buffer thru the socket 
 */
int socket_send(int s, const u_char *payload, size_t size)
{
   /* automatic sizing for strings */
   if (size == 0)
      size = strlen((char *)payload);
   
   /* send data to the socket */
   return send(s, payload, size, 0);
}

/*
 * receive data from the socket
 */
int socket_recv(int sh, u_char *payload, size_t size)
{
   /* read up to size byte */
   return recv(sh, payload, size, 0);
}


/* EOF */

// vim:ts=3:expandtab

