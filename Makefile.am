bin_PROGRAMS= tr/trust_router tid/example/tidc tid/example/tids common/dh_test/tr_dh_test
AM_CPPFLAGS=-I$(srcdir)/include
AM_CFLAGS = -Wall -Werror=missing-prototypes -Werror=strict-prototypes -Wno-parentheses
SUBDIRS = gsscon 
common_srcs = common/tr_name.c \
common/tr_msg.c \
common/tr_dh.c \
	common/tr_util.c

lib_LTLIBRARIES = libtr_tid.la

tr_trust_router_SOURCES = tr/tr_main.c \
common/tr_config.c \
common/tr_idp.c \
common/tr_comm.c \
common/tr_filter.c \
common/tr_constraint.c \
common/tr_rp.c \
tr/tr.c

tr_trust_router_LDADD = gsscon/libgsscon.la libtr_tid.la

tid_example_tidc_SOURCES = tid/example/tidc_main.c 

tid_example_tidc_LDADD = gsscon/libgsscon.la libtr_tid.la

tid_example_tids_SOURCES = tid/example/tids_main.c 

tid_example_tids_LDADD = gsscon/libgsscon.la libtr_tid.la

common_dh_test_tr_dh_test_SOURCES = common/tr_dh.c \
common/dh_test/dh_test.c

libtr_tid_la_SOURCES = tid/tids.c tid/tidc.c tid/tid_req.c tid/tid_resp.c \
$(common_srcs)

libtr_tid_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden
libtr_tid_la_LIBADD = gsscon/libgsscon.la
libtr_tid_la_LDFLAGS = $(AM_LDFLAGS) -version-info 1 -no-undefined

pkginclude_HEADERS = include/trust_router/tid.h include/trust_router/tr_name.h \
	include/trust_router/tr_dh.h \
	include/trust_router/tr_constraint.h \
	include/trust_router/tr_versioning.h 

noinst_HEADERS = include/gsscon.h include/tr_config.h \
	include/tr_msg.h include/tr.h \
	include/tr_idp.h include/tr_rp.h \
	include/tr_comm.h include/tr_apc.h \
	include/tr_filter.h

pkgdata_DATA=schema.sql
systemddir=/lib/systemd/system

systemd_DATA=tids.service


EXTRA_DIST = trust_router.spec
