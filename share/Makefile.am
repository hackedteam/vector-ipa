
include $(top_srcdir)/Makefile.am.common

sysconf_DATA = rcsredirect.conf \
				redirect_fqdn.txt \
				redirect_url.txt \
				redirect_user.txt \
				redirect.html \
				intercept_file.txt

EXTRA_DIST = rcsredirect.conf \
			  	redirect_fqdn.txt \
				redirect_url.txt \
				redirect_user.txt \
				redirect.html \
				intercept_file.txt \
				rcsipa.conf \
				rcsipa.init

install-data-hook:
	install -d $(DESTDIR)/etc/init.d/
	install -m 755 rcsipa.init $(DESTDIR)/etc/init.d/rcsipa
	install -d $(DESTDIR)/etc/conf.d/
	install -m 644 rcsipa.conf $(DESTDIR)/etc/conf.d/rcsipa

uninstall-hook:
	rm -rf $(DESTDIR)/etc/conf.d/rcsipa
	rm -rf $(DESTDIR)/etc/init.d/rcsipa

# vim:ts=4:noexpandtab
