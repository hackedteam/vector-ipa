#!/bin/sh

echo

if test x`which autoconf` = x; then
   echo "ERROR: autoconf not found"
   exit
fi
if test x`which autoheader` = x; then
   echo "ERROR: autoheader not found"
   exit
fi
if test x`which automake` = x; then
   echo "ERROR: automake not found"
   exit
fi
if test x`which aclocal` = x; then
   echo "ERROR: aclocal not found"
   exit
fi

echo "Suggested version:"
echo
echo "     autoconf     2.68"
echo "     automake     1.10.x"
echo
echo "Actual version:"
echo
echo "     `autoconf --version | head -n 1`"
echo "     `automake --version | head -n 1`"

echo "cleaning up config files..."
echo 
rm -f configure
rm -f aclocal.m4
find . -name 'Makefile' -exec rm -f {} \;
find . -name 'Makefile.in' -exec rm -f {} \;

echo "running aclocal"
aclocal
echo "running autoheader"
autoheader
echo "running autoconf"
autoconf
echo "running automake"
automake --add-missing --copy

