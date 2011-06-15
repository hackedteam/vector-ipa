
/* $Id: _strings.h 2854 2010-09-10 15:04:07Z alor $ */

#ifndef __STRINGS_H
#define __STRINGS_H

#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#else
   extern int isprint(int c);
#endif

#ifndef HAVE_STRLCAT
   #include <missing/strlcat.h>
#endif
#ifndef HAVE_STRLCPY
   #include <missing/strlcpy.h>
#endif
#ifndef HAVE_STRSEP
   #include <missing/strsep.h>
#endif
#ifndef HAVE_STRCASESTR
   #include <missing/strcasestr.h>
#endif
#ifndef HAVE_MEMMEM
   #include <missing/memmem.h>
#endif
#ifndef HAVE_BASENAME
   #include <missing/basename.h>
#elif defined OS_MACOSX
	#include <libgen.h>
#endif

int match_pattern(const char *s, const char *pattern);
int base64_decode(char *bufplain, const char *bufcoded);
int strescape(char *dst, char *src);
int str_replace(char **text, const char *s, const char *d);
size_t strlen_utf8(const char *s);
char * my_strtok(char *s, const char *delim, char **ptrptr);
void str_decode_url(u_char *src);
int str_hex_to_bytes(char *string, u_char *bytes);
char * str_tohex(u_char *bin, size_t len, char *dst, size_t dst_len);
char * hex_format(const u_char *buf, size_t len, char *dst);

#define HEX_CHAR_PER_LINE 16
#define strtok(x,y) DON_T_USE_STRTOK_DIRECTLY_USE__MY_STRTOK__INSTEAD

#endif

/* EOF */

// vim:ts=3:expandtab

