
dnl $Id: acinclude.m4 31 2006-07-03 15:57:13Z alor $

dnl
dnl MY_MESSAGE(MESSAGE)
dnl

AC_DEFUN([MY_MESSAGE],
[
   AC_MSG_RESULT()
   AC_MSG_RESULT(${SB}$1...${EB})
   AC_MSG_RESULT()
])

dnl
dnl MY_CHECK_OPTION(STRING, VAR)
dnl

AC_DEFUN([MY_CHECK_OPTION],
[
   echo "$1 ${SB}$2${EB}"
])


dnl
dnl MY_CHECK_FUNC(lib, func, ldflags, libs, action-if-found, action-if-not-found)
dnl

AC_DEFUN([MY_CHECK_FUNC],
[
   OLDLDFLAGS="${LDFLAGS}"
   OLDLIBS="${LIBS}"
   LDFLAGS="$3"
   LIBS="$4"
   AC_CHECK_LIB($1, $2, $5, $6)
   LDFLAGS="${OLDLDFLAGS}"
   LIBS="${OLDLIBS}"

])

dnl
dnl MY_PTHREAD_CHECK()
dnl

AC_DEFUN([MY_PTHREAD_CHECK],
[
   AC_SEARCH_LIBS(pthread_create, c_r pthread,,)
   
   if test "$OS" = "SOLARIS"; then
      AC_SEARCH_LIBS(_getfp, pthread,,)
   elif test "$OS" != "MACOSX" -a "$OS" != "WINDOWS"; then
      AC_MSG_CHECKING(whether $CC accepts -pthread)
      LDFLAGS_store="$LDFLAGS"
      LDFLAGS="$LDFLAGS -pthread"
      AC_TRY_LINK([
         #include <pthread.h>
         ],
         [
            int main(int argc, char **argv)
            {
               pthread_create(NULL, NULL, NULL, NULL);
               return 0;
            }
         ],
         [AC_MSG_RESULT(yes)],
         [AC_MSG_RESULT(no)
            LDFLAGS="$LDFLAGS_store"
            AC_MSG_WARN(***************************);
            AC_MSG_WARN(* PTHREAD ARE REQUIRED !! *);
            AC_MSG_WARN(***************************);
            exit
         ])
      unset LDFLAGS_store
   fi

])


dnl
dnl MY_GCC_MACRO()
dnl
dnl check if the compiler support __VA_ARGS__ in macro declarations
dnl

AC_DEFUN([MY_GCC_MACRO],
[
   AC_MSG_CHECKING(if your compiler supports __VA_ARGS__ in macro declarations)
   
   AC_TRY_RUN([
   
      #include <stdio.h>

      #define EXECUTE(x, ...) do{ if (x != NULL) x( __VA_ARGS__ ); }while(0)

      void foo() { }
      
      int main(int argc, char **argv)
      {
         EXECUTE(foo);
         return 0;
      } 
   ],
   [ AC_MSG_RESULT(yes) ],
   [ AC_MSG_RESULT(no) 
     AC_ERROR(please use gcc >= 3.2.x)
   ],
     AC_MSG_RESULT(unkown when cross-compiling)
   )
])

dnl
dnl MY_RESOLVE_CHECK()
dnl

AC_DEFUN([MY_RESOLVE_CHECK],
[
   AC_SEARCH_LIBS(dn_expand, resolv c,
      [
         AC_MSG_CHECKING(for additional -lresolv needed by dn_expand)
         AC_TRY_LINK([
               #include <sys/types.h>
               #include <netinet/in.h>
               #include <arpa/nameser.h>
               #include <resolv.h>
            ],
            [
               int main(int argc, char **argv)
               {
                  char *q;
                  char p[NS_MAXDNAME];

                  dn_expand(q, q, q, p, sizeof(p));
               } 
            ],
            [AC_MSG_RESULT(not needed)],
            [AC_MSG_RESULT(needed)
             LIBS="$LIBS -lresolv"]
         )
         AM_CONDITIONAL(HAVE_DN_EXPAND, true) ac_ec_dns=yes 
      ],
      [AM_CONDITIONAL(HAVE_DN_EXPAND, false) ac_ec_dns=no])

])

dnl vim:ts=3:expandtab
