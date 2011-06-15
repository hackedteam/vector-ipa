#!/bin/sh

echo

if test ! -f ./configure; then
   echo "ERROR: configure not found..."
   echo "Running autogen.sh to generate the autoscripts"
   if test ! -f ./autogen.sh; then
      echo "FATAL: autogen.sh not found."
      exit
   fi
   ./autogen.sh
fi

if test "$1" = "--renew"; then
   shift
   ./autogen.sh
fi

echo "Configuring for maintainers mode..."
echo 
./configure --enable-debug --enable-maintainer-mode $* || exit 

echo
echo "Making the executable to be tested in the current directory"
echo 
make test
