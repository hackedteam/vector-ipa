/*
    MODULE -- data handling module

    Copyright (C) Alberto Ornaghi

    $Id: file.c 3010 2010-10-18 12:51:24Z alor $
*/

#include <main.h>
#include <file.h>

#include <libgen.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

/* protos */

char * get_full_path(const char *dir, const char *file);
char * get_local_path(const char *dir, const char *file);
char * get_path(const char *dir, const char *file);
FILE * open_data(char *dir, char *file, char *mode);
FILE * create_file(char *full_path, char *mode);

int file_open(char *path);
int file_read(int fd, void **buf, int len);
int file_close(int fd);
int file_relative_path(char *fullpath, char *base_path, char **relative_path);
int file_absolute_path(char *base_path, char *relative_path, char **fullpath);
int file_is_type(char *path, char *base_path, int flag);
off_t file_get_size(char *path, char *base_path);
char *file_substitute_path(char *fullpath, char *fromstring, char *tostring, char **result);

/*******************************************/

/*
 * add the prefix to a given filename
 */

char * get_full_path(const char *dir, const char *file)
{
   char *filename;
   int len = 256;

   SAFE_CALLOC(filename, len, sizeof(char));

   if (!strcmp(dir, "etc"))
      snprintf(filename, len, "%s/%s", INSTALL_SYSCONFDIR, file);

   if (!strcmp(dir, "vectors"))
	   snprintf(filename, len, "%s/%s/%s", INSTALL_SYSCONFDIR, dir, file);

   DEBUG_MSG(D_VERBOSE, "get_full_path -- [%s] %s", dir, filename);

   return filename;
}

/*
 * add the local path to a given filename
 */

char * get_local_path(const char *dir, const char *file)
{
   char *filename;
   char *self_root = ".";

   SAFE_CALLOC(filename, strlen(self_root) + strlen("/share/vectors/") + strlen(file) + 1, sizeof(char));

   if (!strcmp(dir, "etc"))
      sprintf(filename, "%s/share/%s", self_root, file);

   if (!strcmp(dir, "vectors"))
      sprintf(filename, "%s/share/vectors/%s", self_root, file);

   DEBUG_MSG(D_VERBOSE, "get_local_path -- %s", filename);

   return filename;
}

/*
 * return the path of the file
 * search first globally, then locally
 */
char * get_path(const char *dir, const char *file)
{
   FILE *fd;
   char *filename = NULL;

   filename = get_full_path(dir, file);

   DEBUG_MSG(D_DEBUG, "get_path: %s", filename);

   fd = fopen(filename, FOPEN_READ_BIN);
   if (fd == NULL) {
      SAFE_FREE(filename);
      filename = get_local_path(dir, file);

      DEBUG_MSG(D_DEBUG, "get_path: dropping to %s", filename);
   } else {
      fclose(fd);
   }

   return filename;
}


/*
 * opens a file in the share directory.
 * first look in the installation path, then locally.
 */

FILE * open_data(char *dir, char *file, char *mode)
{
   FILE *fd;
   char *filename = NULL;

   filename = get_full_path(dir, file);

   DEBUG_MSG(D_INFO, "open_data %s", filename);

   fd = fopen(filename, mode);
   if (fd == NULL) {
      SAFE_FREE(filename);
      filename = get_local_path(dir, file);

      DEBUG_MSG(D_INFO, "open_data dropping to %s", filename);

      fd = fopen(filename, mode);
      /* don't check the fd, it is done by the caller */
   }

   SAFE_FREE(filename);

   return fd;
}

FILE * create_file(char *full_path, char *mode)
{
   FILE *fd;
   char *p;
   int ret;
   char *temp = strdup(full_path);
   char path[256];

   DEBUG_MSG(D_INFO, "create_file: [%s]", full_path);

   /* get only the directory path */
   temp = dirname(temp);

   /* save the current working dir */
   p = getcwd(path, sizeof(path));

   /* start always from the root */
   ret = chdir("/");

   /* create the complete subtree */
   for (p = strsep(&temp, "/"); p != NULL; p = strsep(&temp, "/")) {
      mkdir(p, 0755);
      ret = chdir(p);
   }

   /* restore the old working dir */
   ret = chdir(path);

   SAFE_FREE(temp);

   /* open the file and return the filedesc */
   fd = fopen(full_path, mode);

   if (fd == NULL)
      DEBUG_MSG(D_ERROR, "create_file: cannot create [%s]", full_path);

   return fd;
}

int file_open(char *path)
{
   int fd;

   fd = open(path, O_RDONLY);
   if (fd < 0)
      FATAL_ERROR("error opening file %s", path);

   return fd;
}

int file_read(int fd, void **buf, int len)
{
	int n = 0;

	while (n < len) {
		int ret;

		ret = read(fd, *buf + n, len - n);
		if (ret == -1)
			return -1;

		n += ret;
	}

	return n;
}

int file_close(int fd)
{
   int ret;

   ret = close(fd);
   if (ret == -1)
      FATAL_ERROR("%s: error closing file");

   return ESUCCESS;
}

int file_relative_path(char *fullpath, char *base_path, char **relative_path)
{
	char *laststr;

   if (!fullpath || !relative_path)
      FATAL_ERROR("%s: wrong parameters [fullpath %p][relative_path %p]",
	    __func__,
	    fullpath,
	    relative_path
	    );

	laststr = strstr(fullpath, base_path) + strlen(base_path);

	if (laststr[0] == '/')
		laststr++;

   SAFE_STRDUP(*relative_path, laststr);

	DEBUG_MSG(D_INFO, "%s [relative_path %s]", __func__, *relative_path);

   return ESUCCESS;
}

int file_absolute_path(char *base_path, char *relative_path, char **fullpath)
{
   if ( !fullpath )
      FATAL_ERROR("%s: NULL argument [fullpath %p]", __func__, fullpath);

   if ( !base_path )
      FATAL_ERROR("%s: NULL argument [basepath %p]", __func__, base_path);

   if ( !relative_path )
      FATAL_ERROR("%s: NULL argument [relative_path %p]", __func__, relative_path);

   if (base_path[0] != '/') {
      DEBUG_MSG(D_ERROR, "%s: base path argument does not begin with '/' [base_path %s]", __func__, base_path);
      return -EINVALID;
   }

   SAFE_CALLOC(*fullpath, 1, strlen(base_path) + strlen(relative_path) + 3);
   sprintf(*fullpath, "%s/%s", base_path, relative_path);

   return ESUCCESS;
}

int file_is_type(char *path, char *base_path, int flag)
{
	struct stat *s;
	char *fullpath;
	int ret;

	SAFE_CALLOC(s, 1, sizeof(struct stat));

	if (base_path) {
		ret = file_absolute_path(base_path, path, &fullpath);
		if (ret != ESUCCESS)
			return -EFAILURE;
	} else
		fullpath = path;

	ret = stat(fullpath, s);
	if (ret < 0) {
		// DEBUG_MSG(D_ERROR, "%s error performing stat on %s [%s]", __func__, fullpath, strerror(errno));
		return -EINVALID;
	}

	if (fullpath != path)
		SAFE_FREE(fullpath);

	if (s->st_mode & flag) {
		SAFE_FREE(s);
		return ESUCCESS;
	}

	SAFE_FREE(s);
	return -EFAILURE;
}

off_t file_get_size(char *path, char *base_path)
{
   struct stat *s;
   char *fullpath;
   int ret;
   off_t size;

   SAFE_CALLOC(s, 1, sizeof(struct stat));

   if (base_path) {
      ret = file_absolute_path(base_path, path, &fullpath);
      if (ret != ESUCCESS)
	 return -EFAILURE;
   } else
      fullpath = path;

   ret = stat(fullpath, s);
   if (ret < 0) {
      DEBUG_MSG(D_ERROR, "error performing stat on %s", fullpath);
      return -EINVALID;
   }

   if (fullpath != path)
      SAFE_FREE(fullpath);

   size = s->st_size;

   SAFE_FREE(s);

   return size;
}

char *file_substitute_path(char *fullpath, char *fromstring, char *tostring, char **result)
{
	u_int size;
	char *fsptr; // fromstring pointer

	// size of final string, without null termination
	size = strlen(fullpath) - strlen(fromstring) + strlen(tostring);

	SAFE_CALLOC(*result, 1, size + 1);

	fsptr = strstr(fullpath, fromstring);
	strlcpy(*result, fullpath, fsptr - fullpath);
	strlcpy(*result + ( fsptr - fullpath - 1), tostring, strlen(tostring));
	strlcpy(*result + ( fsptr - fullpath + strlen(tostring)), fsptr + strlen(fromstring), strlen(fsptr + strlen(fromstring)));

	return *result;
}


/* EOF */

// vim:ts=3:expandtab

