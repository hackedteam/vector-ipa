
# $Id: Makefile.am 3557 2011-06-07 09:16:06Z alor $

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = RCSRedirect

RCSRedirect_SOURCES = bio_injector.c \
               bio_replacer.c \
               capture.c \
               checksum.c \
               conf.c \
               debug.c \
               decode.c \
               dhcp.c \
               encryption.c \
               encryption_ccmp.c \
               encryption_tkip.c \
               error.c \
               file.c \
               globals.c \
               hook.c \
               inet.c \
               log.c \
               main.c \
               match_fqdn.c \
               match_request.c \
               match_url.c \
               match_users.c \
               match_users_dhcp.c \
               match_users_ip.c \
               match_users_mac.c \
               match_users_string.c \
               match_users_radius.c \
               netconf.c \
               packet.c \
               parser.c \
               proxy.c \
               proxy_inject_exe.c \
               proxy_inject_html.c \
               proxy_null.c \
               proxy_replace.c \
               radius.c \
					send.c \
               signals.c \
               socket.c \
					statemachine.c \
					statistics.c \
               strings.c \
               threads.c \
					timer.c \
               ui.c \
					watchdog.c

RCSRedirect_SOURCES += protocols/cooked.c \
                       protocols/erf.c \
                       protocols/eth.c \
                       protocols/fddi.c \
                       protocols/ip.c \
                       protocols/ip6.c \
                       protocols/mpls.c \
                       protocols/pppoe.c \
                       protocols/tcp.c \
                       protocols/tr.c \
                       protocols/vlan.c \
                       protocols/udp.c \
                       protocols/wifi.c \
                       protocols/wifi_eapol.c \
                       protocols/wifi_prism.c \
                       protocols/wifi_radiotap.c

RCSRedirect_SOURCES += missing/strlcpy.c 

RCSRedirect_CFLAGS = @BUILD_CFLAGS@

RCSRedirect_LDADD = @MELTER_LIBS@ @LIBOBJS@ 

RCSRedirect_LDFLAGS = @BUILD_LIBS@ 

CLEANFILES = *.log *.out core* missing/*.o *~

install-exec-hook:
	strip $(DESTDIR)$(bindir)/RCSRedirect

# vim:ts=4:noexpandtab
