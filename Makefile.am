bin_PROGRAMS= tr/tr tid/example/tidc tid/example/tids common/dh_test/dh_test
AM_CPPFLAGS=-I$(srcdir)/include
SUBDIRS = gsscon 
common_srcs = common/tr_name.c \
common/tr_msg.c \
common/tr_dh.c

lib_LTLIBRARIES = libtr_tid.la

tr_tr_SOURCES = tr/tr_main.c \
common/tr_config.c 

tr_tr_LDADD = gsscon/libgsscon.la libtr_tid.la

tid_example_tidc_SOURCES = tid/example/tidc_main.c 

tid_example_tidc_LDADD = gsscon/libgsscon.la libtr_tid.la

tid_example_tids_SOURCES = tid/example/tids_main.c 

tid_example_tids_LDADD = gsscon/libgsscon.la libtr_tid.la

common_dh_test_dh_test_SOURCES = common/tr_dh.c \
common/dh_test/dh_test.c

libtr_tid_la_SOURCES = tid/tids.c tid/tidc.c \
$(common_srcs)

libtr_tid_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden
libtr_tid_la_LIBADD = gsscon/libgsscon.la
libtr_tid_la_LDFLAGS = $(AM_LDFLAGS) -version-info 0 -no-undefined

pkginclude_HEADERS = include/trust_router/tid.h include/trust_router/tr_name.h \
include/trust_router/tr_versioning.h

noinst_HEADERS = include/gsscon.h include/tr_config.h \
include/tr_msg.h \
include/tr.h \
include/tr_dh.h

