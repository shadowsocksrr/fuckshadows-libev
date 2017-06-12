VERSION_INFO = 2:0:0

if ENABLE_OPTIMIZATION
AM_CFLAGS = -O3 -pipe -ffast-math -ftree-vectorize -Wall -Werror -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE
else
AM_CFLAGS = -Os -Wall -Werror -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE
endif

AM_CFLAGS += $(PTHREAD_CFLAGS)
if !USE_SYSTEM_SHARED_LIB
AM_CFLAGS += -I$(top_srcdir)/libev
AM_CFLAGS += -I$(top_srcdir)/libudns
AM_CFLAGS += -I$(top_srcdir)/libsodium/src/libsodium/include
endif
AM_CFLAGS += -I$(top_srcdir)/libipset/include
AM_CFLAGS += -I$(top_srcdir)/libcork/include
AM_CFLAGS += $(LIBPCRE_CFLAGS)

FS_COMMON_LIBS = $(top_builddir)/libipset/libipset.la \
                 $(top_builddir)/libcork/libcork.la \
                 $(INET_NTOP_LIB) $(LIBPCRE_LIBS)
if USE_SYSTEM_SHARED_LIB
FS_COMMON_LIBS += -lev -lsodium -lm
else
FS_COMMON_LIBS += $(top_builddir)/libev/libev.la \
                  $(top_builddir)/libsodium/src/libsodium/libsodium.la
endif

bin_PROGRAMS = fs-local fs-tunnel
if !BUILD_WINCOMPAT
bin_PROGRAMS += fs-server fs-manager
endif

bloom_src = MurmurHash3.c \
            bloom.c

sni_src = http.c \
          tls.c \
          rule.c

crypto_src = crypto.c \
             aead.c \
             stream.c \
             $(bloom_src) \
             ppbloom.c

fs_local_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   udprelay.c \
                   cache.c \
                   acl.c \
                   netutils.c \
                   local.c \
                   $(crypto_src) \
                   $(sni_src)

fs_tunnel_SOURCES = utils.c \
                    jconf.c \
                    json.c \
                    udprelay.c \
                    cache.c \
                    netutils.c \
                    tunnel.c \
                    $(crypto_src)

fs_server_SOURCES = utils.c \
                    netutils.c \
                    jconf.c \
                    json.c \
                    udprelay.c \
                    cache.c \
                    acl.c \
                    resolv.c \
                    server.c \
                    $(crypto_src) \
                    $(sni_src)

fs_manager_SOURCES = utils.c \
                     jconf.c \
                     json.c \
                     netutils.c \
                     manager.c

fs_local_LDADD = $(FS_COMMON_LIBS)
fs_tunnel_LDADD = $(FS_COMMON_LIBS)
fs_server_LDADD = $(FS_COMMON_LIBS)
fs_manager_LDADD = $(FS_COMMON_LIBS)
if USE_SYSTEM_SHARED_LIB
fs_local_LDADD += -ludns
fs_tunnel_LDADD += -ludns
fs_server_LDADD += -ludns
fs_manager_LDADD += -ludns
else
fs_local_LDADD += $(top_builddir)/libudns/libudns.la
fs_tunnel_LDADD += $(top_builddir)/libudns/libudns.la
fs_server_LDADD += $(top_builddir)/libudns/libudns.la
fs_manager_LDADD += $(top_builddir)/libudns/libudns.la
endif

fs_local_CFLAGS = $(AM_CFLAGS) -DMODULE_LOCAL
fs_tunnel_CFLAGS = $(AM_CFLAGS) -DMODULE_TUNNEL
fs_server_CFLAGS = $(AM_CFLAGS) -DMODULE_REMOTE
fs_manager_CFLAGS = $(AM_CFLAGS) -DMODULE_MANAGER

if BUILD_WINCOMPAT
fs_local_SOURCES += win32.c
fs_tunnel_SOURCES += win32.c
endif

if BUILD_REDIRECTOR
bin_PROGRAMS += fs-redir
fs_redir_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   netutils.c \
                   cache.c \
                   udprelay.c \
                   redir.c \
                   $(crypto_src) \
                   $(sni_src)

fs_redir_CFLAGS = $(AM_CFLAGS) -DMODULE_REDIR
fs_redir_LDADD = $(FS_COMMON_LIBS)
if USE_SYSTEM_SHARED_LIB
fs_redir_LDADD += -ludns
else
fs_redir_LDADD += $(top_builddir)/libudns/libudns.la
endif
endif
