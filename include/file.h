
/* $Id: file.h 2937 2010-09-30 12:37:30Z alor $ */

#ifndef __FILE_H
#define __FILE_H

#include <sys/types.h>
#include <stdio.h>

extern FILE * open_data(char *dir, char *file, char *mode);
extern char * get_full_path(const char *dir, const char *file);
extern char * get_local_path(const char *dir, const char *file);
extern char * get_path(const char *dir, const char *file);

extern FILE * create_file(char *full_path, char *mode);

extern int file_open(char *path);
extern int file_read(int fd, void **buf, int len);
extern int file_close(int fd);
extern int file_relative_path(char *fullpath, char *base_path, char **relative_path);
extern int file_absolute_path(char *base_path, char *relative_path, char **fullpath);
extern int file_is_type(char *path, char *base_path, int flag);
extern off_t file_get_size(char *path, char *base_path);
extern char *file_substitute_path(char *fullpath, char *fromstring, char *tostring, char **result);

#define CONF_FILE                "rcsredirect.conf"

/* fopen modes */
#define FOPEN_READ_TEXT   "r"
#define FOPEN_READ_BIN    "rb"
#define FOPEN_WRITE_TEXT  "w"
#define FOPEN_WRITE_BIN   "wb"

#define MAX_FILENAME_LEN   512

#endif

/* EOF */

// vim:ts=3:expandtab

