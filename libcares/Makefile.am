AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# When using the low-level hard-hacking memory leak tracking code from
# libcurl the generated curl/curlbuild.h file must also be reachable.
# Using the libcurl lowlevel code from within c-ares library is ugly and
# only works when c-ares is built and linked with a similarly debug-build
# libcurl, but we do this anyway for convenience.
#
# $(top_builddir)/../include/curl for generated curlbuild.h included from curl.h
# $(top_builddir)/../include is for libcurl's generated curl/curlbuild.h file
# $(top_srcdir)/../include is for libcurl's external include files
# $(top_builddir)/../lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/../lib is for libcurl's lib/setup.h and other "private" files
# $(top_builddir) is for c-ares's generated ares_config.h file
# $(top_srcdir) is for c-ares's ares_setup.h and other "c-ares-private" files

AM_CPPFLAGS = -I$(top_builddir)/libcares \
              -I$(top_srcdir)/libcares

noinst_LTLIBRARIES = libcares.la

# adig and ahost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = AUTHORS CHANGES README.cares Makefile.inc Makefile.dj	   \
 Makefile.m32 Makefile.netware Makefile.msvc Makefile.Watcom $(man_MANS)   \
 config-win32.h RELEASE-NOTES libcares.pc.in buildconf get_ver.awk maketgz \
 TODO ares_build.h.in cares.rc README.msvc $(MSVCFILES)	   \
 $(CSOURCES) $(HHEADERS) config-dos.h acountry.1 adig.1 ahost.1 INSTALL.md	   \
 README.md LICENSE.md RELEASE-PROCEDURE.md

DISTCLEANFILES = ares_build.h

CARES_VERSION_INFO = -version-info 4:0:2

libcares_la_LDFLAGS = -static $(CARES_VERSION_INFO)

libcares_la_CPPFLAGS_EXTRA = -DCARES_BUILDING_LIBRARY -DCARES_STATICLIB

libcares_la_CFLAGS = -I$(top_srcdir)/libcares

libcares_la_CPPFLAGS = $(AM_CPPFLAGS) $(libcares_la_CPPFLAGS_EXTRA)

# Makefile.inc provides the CSOURCES and HHEADERS defines
CSOURCES = ares__close_sockets.c	\
  ares__get_hostent.c			\
  ares__read_line.c			\
  ares__timeval.c			\
  ares_cancel.c				\
  ares_data.c				\
  ares_destroy.c			\
  ares_expand_name.c			\
  ares_expand_string.c			\
  ares_fds.c				\
  ares_free_hostent.c			\
  ares_free_string.c			\
  ares_getenv.c				\
  ares_gethostbyaddr.c			\
  ares_gethostbyname.c			\
  ares_getnameinfo.c			\
  ares_getsock.c			\
  ares_init.c				\
  ares_library_init.c			\
  ares_llist.c				\
  ares_mkquery.c			\
  ares_create_query.c			\
  ares_nowarn.c				\
  ares_options.c			\
  ares_parse_a_reply.c			\
  ares_parse_aaaa_reply.c		\
  ares_parse_mx_reply.c			\
  ares_parse_naptr_reply.c		\
  ares_parse_ns_reply.c			\
  ares_parse_ptr_reply.c		\
  ares_parse_soa_reply.c		\
  ares_parse_srv_reply.c		\
  ares_parse_txt_reply.c		\
  ares_platform.c			\
  ares_process.c			\
  ares_query.c				\
  ares_search.c				\
  ares_send.c				\
  ares_strcasecmp.c			\
  ares_strdup.c				\
  ares_strerror.c			\
  ares_timeout.c			\
  ares_version.c			\
  ares_writev.c				\
  bitncmp.c				\
  inet_net_pton.c			\
  inet_ntop.c				\
  windows_port.c

HHEADERS = ares.h			\
  ares_build.h				\
  ares_data.h				\
  ares_dns.h				\
  ares_getenv.h				\
  ares_inet_net_pton.h			\
  ares_iphlpapi.h			\
  ares_ipv6.h				\
  ares_library_init.h			\
  ares_llist.h				\
  ares_nowarn.h				\
  ares_platform.h			\
  ares_private.h			\
  ares_rules.h				\
  ares_strcasecmp.h			\
  ares_strdup.h				\
  ares_version.h			\
  ares_writev.h				\
  bitncmp.h				\
  nameser.h				\
  ares_setup.h				\
  setup_once.h

libcares_la_SOURCES = $(CSOURCES) $(HHEADERS)

# Make files named *.dist replace the file without .dist extension
dist-hook:
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist"`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)
