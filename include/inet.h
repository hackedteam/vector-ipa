
/* $Id: inet.h 2653 2010-07-06 07:31:19Z alor $ */

#ifndef __INET_H
#define __INET_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <sys/stat.h>

enum {
   NS_IN6ADDRSZ            = 16,
   NS_INT16SZ              = 2,

   ETH_ADDR_LEN            = 6,
   TR_ADDR_LEN             = 6,
   FDDI_ADDR_LEN           = 6,
   MEDIA_ADDR_LEN          = 6,

   IP4_ADDR_LEN            = 4,
   IP6_ADDR_LEN            = 16,
   MAX_IP_ADDR_LEN         = IP6_ADDR_LEN,

   ETH_ASCII_ADDR_LEN      = sizeof("ff:ff:ff:ff:ff:ff")+1,
   IP4_ASCII_ADDR_LEN      = sizeof("255.255.255.255")+1,
   IP6_ASCII_ADDR_LEN      = sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")+1,
   MAX_ASCII_ADDR_LEN      = IP6_ASCII_ADDR_LEN,
};

/*
 * this structure is used by the program to handle
 * an IP packet disregarding its version
 */
struct ip_addr {
   u_int16 addr_type;
   u_int16 addr_len;
   /* this must be aligned in memory */
   u_int8 addr[MAX_IP_ADDR_LEN];
};

int ip_addr_init(struct ip_addr *sa, u_int16 type, u_char *addr);
int ip_addr_cmp(struct ip_addr *sa, struct ip_addr *sb);
int ip_addr_in_range(struct ip_addr *ip, struct ip_addr *sa, struct ip_addr *sb);
int ip_addr_is_zero(struct ip_addr *sa);

char *ip_addr_ntoa(struct ip_addr *sa, char *dst);
char *mac_addr_ntoa(u_char *mac, char *dst);
int mac_addr_aton(char *str, u_char *mac);

int inet_valid_ip(const char *string);

const char *inet_ntop4(const u_char *src, char *dst, size_t size);
const char *inet_ntop6(const u_char *src, char *dst, size_t size);

/********************/

#ifdef WORDS_BIGENDIAN
   /* BIG ENDIAN */
   #define phtos(x) ( (u_int16)                       \
                      ((u_int16)*((u_int8 *)x+1)<<8|  \
                      (u_int16)*((u_int8 *)x+0)<<0)   \
                    )

   #define phtol(x) ( (u_int32)*((u_int8 *)x+3)<<24|  \
                      (u_int32)*((u_int8 *)x+2)<<16|  \
                      (u_int32)*((u_int8 *)x+1)<<8|   \
                      (u_int32)*((u_int8 *)x+0)<<0    \
                    )

   #define pntos(x) ( (u_int16)                       \
                      ((u_int16)*((u_int8 *)x+1)<<0|  \
                      (u_int16)*((u_int8 *)x+0)<<8)   \
                    )

   #define pntol(x) ( (u_int32)*((u_int8 *)x+3)<<0|   \
                      (u_int32)*((u_int8 *)x+2)<<8|   \
                      (u_int32)*((u_int8 *)x+1)<<16|  \
                      (u_int32)*((u_int8 *)x+0)<<24   \
                    )

   /* return little endian */
   #define htons_inv(x) (u_int16)(x << 8) | (x >> 8)

#else
   /* LITTLE ENDIAN */
   #define phtos(x) *(u_int16 *)(x)
   #define phtol(x) *(u_int32 *)(x)

   #define pntos(x) ntohs(*(u_int16 *)(x))
   #define pntol(x) ntohl(*(u_int32 *)(x))

   /* return little endian */
   #define htons_inv(x) (u_int16)x

#endif


#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))

#define ip_addr_to_int32(x)  *(u_int32 *)(x)

#endif


/* EOF */

// vim:ts=3:expandtab

