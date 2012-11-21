AM_CPPFLAGS=-I$(top_srcdir)/include

noinst_LTLIBRARIES = libgsscon.la
noinst_PROGRAMS=test/gsscon_client test/gsscon_server
libgsscon_la_SOURCES = gsscon_active.c gsscon_common.c gsscon_passive.c

test_gsscon_client_LDADD = libgsscon.la
test_gsscon_client_SOURCES = test/gsscon_client.c

test_gsscon_server_LDADD = libgsscon.la
test_gsscon_server_SOURCES = test/gsscon_server.c
