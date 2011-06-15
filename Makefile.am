
include $(top_srcdir)/Makefile.am.common

SUBDIRS = share include src 

EXTRA_DIST = CHANGELOG \
             TODO \
             Makefile.am.common \
             shtool 

CLEANFILES = -R auto4te.cache *~ *.log *.out *.cache 

test: all
	ln -fs ./src/RCSRedirect ./
	./shtool fixperm ./

# vim:ts=4:noexpandtab

