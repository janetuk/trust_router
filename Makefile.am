DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
bin_PROGRAMS= tr/trust_router tr/trpc tid/example/tidc tid/example/tids common/tests/tr_dh_test common/tests/mq_test common/tests/thread_test trp/msgtst trp/test/rtbl_test trp/test/ptbl_test common/tests/cfg_test common/tests/commtest
AM_CPPFLAGS=-I$(srcdir)/include $(GLIB_CFLAGS)
AM_CFLAGS = -Wall -Werror=missing-prototypes -Werror -Wno-parentheses $(GLIB_CFLAGS)
SUBDIRS = gsscon 
common_srcs = common/tr_name.c \
	common/tr_constraint.c \
	common/jansson_iterators.h \
	common/tr_msg.c \
	common/tr_dh.c \
        common/tr_debug.c \
	common/tr_util.c \
	common/tr_apc.c \
	common/tr_comm.c \
	common/tr_rp.c \
	common/tr_idp.c \
	common/tr_filter.c \
	common/tr_gss.c

tid_srcs = tid/tid_resp.c \
tid/tid_req.c \
tid/tids.c \
tid/tidc.c

trp_srcs = trp/trp_conn.c \
trp/trps.c \
trp/trpc.c \
trp/trp_ptable.c \
trp/trp_rtable.c \
trp/trp_req.c \
trp/trp_upd.c \
tid/tid_resp.c \
tid/tid_req.c \
common/tr_gss.c \
common/tr_config.c \
common/tr_idp.c \
common/tr_apc.c \
common/tr_comm.c \
common/tr_filter.c \
common/tr_rp.c \
common/tr_msg.c \
common/tr_constraint.c \
common/tr_name.c \
common/tr_mq.c

check_PROGRAMS = common/t_constraint
TESTS = common/t_constraint

lib_LTLIBRARIES = libtr_tid.la

libtr_tid_la_SOURCES = $(tid_srcs) \
$(common_srcs) \
trp/trp_req.c \
trp/trp_upd.c

libtr_tid_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden
libtr_tid_la_LIBADD = gsscon/libgsscon.la $(GLIB_LIBS)
libtr_tid_la_LDFLAGS = $(AM_LDFLAGS) -version-info 2 -no-undefined

common_t_constraint_SOURCES = common/t_constraint.c \
common/tr_debug.c \
common/tr_name.c \
common/tr_constraint.c \
tid/tid_req.c \
tid/tid_resp.c

common_t_constraint_CPPFLAGS = $(AM_CPPFLAGS) -DTESTS=\"$(srcdir)/common/tests.json\"
common_t_constraint_LDADD = gsscon/libgsscon.la 

tr_trust_router_SOURCES =tr/tr_main.c \
tr/tr.c \
tr/tr_event.c \
tr/tr_cfgwatch.c \
tr/tr_tid.c \
tr/tr_trp.c \
$(trp_srcs)

tr_trust_router_CFLAGS = $(AM_CFLAGS) -pthread
tr_trust_router_LDFLAGS = $(AM_LDFLAGS) -levent_pthreads -pthread
tr_trust_router_LDADD = gsscon/libgsscon.la libtr_tid.la $(GLIB_LIBS)

tr_trpc_SOURCES =tr/trpc_main.c \
tr/tr_trp.c \
$(trp_srcs)
tr_trpc_LDADD = gsscon/libgsscon.la libtr_tid.la $(GLIB_LIBS)
tr_trpc_LDFLAGS = $(AM_LDFLAGS) -pthread
tr_trpc_CFLAGS = $(AM_CFLAGS) -pthread

trp_msgtst_SOURCES = trp/msgtst.c \
common/tr_msg.c \
common/tr_comm.c \
common/tr_apc.c \
common/tr_rp.c \
common/tr_idp.c \
common/tr_gss.c \
common/tr_filter.c \
trp/trp_req.c \
trp/trp_upd.c \
tid/tid_resp.c \
tid/tid_req.c
trp_msgtst_LDADD = libtr_tid.la $(GLIB_LIBS)

trp_test_rtbl_test_SOURCES = trp/test/rtbl_test.c \
common/tr_name.c \
common/tr_gss.c \
common/tr_debug.c \
trp/trp_rtable.c
trp_test_rtbl_test_LDADD =  $(GLIB_LIBS)

trp_test_ptbl_test_SOURCES = trp/test/ptbl_test.c \
$(trp_srcs) 
trp_test_ptbl_test_LDADD = gsscon/libgsscon.la libtr_tid.la $(GLIB_LIBS)

tid_example_tidc_SOURCES = tid/example/tidc_main.c
tid_example_tidc_LDADD = gsscon/libgsscon.la libtr_tid.la $(GLIB_LIBS)

tid_example_tids_SOURCES = tid/example/tids_main.c
tid_example_tids_LDADD = gsscon/libgsscon.la libtr_tid.la $(GLIB_LIBS)

common_tests_tr_dh_test_SOURCES = common/tr_dh.c \
common/tr_debug.c \
common/tests/dh_test.c

common_tests_mq_test_SOURCES = common/tr_mq.c \
common/tests/mq_test.c

common_tests_mq_test_CFLAGS = -pthread
common_tests_mq_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc

common_tests_cfg_test_SOURCES = common/tests/cfg_test.c \
$(trp_srcs)

common_tests_cfg_test_LDADD = gsscon/libgsscon.la libtr_tid.la $(GLIB_LIBS)
common_tests_cfg_test_CFLAGS = -pthread
common_tests_cfg_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc

common_tests_thread_test_SOURCES = common/tr_mq.c \
common/tr_debug.c \
common/tests/thread_test.c

common_tests_thread_test_CFLAGS = -pthread
common_tests_thread_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc

common_tests_commtest_SOURCES = common/tests/commtest.c \
$(trp_srcs)
common_tests_commtest_LDADD = gsscon/libgsscon.la libtr_tid.la $(GLIB_LIBS)
common_tests_commtest_CFLAGS = -pthread
common_test_commtest_LDFLAGS = $(AM_LDFLAGS) -ltalloc

pkginclude_HEADERS = include/trust_router/tid.h include/trust_router/tr_name.h \
	include/tr_debug.h \
	include/trust_router/tr_dh.h \
	include/trust_router/tr_constraint.h \
	include/trust_router/tr_versioning.h 

noinst_HEADERS = include/gsscon.h include/tr_config.h \
	include/tr_msg.h include/tr.h \
	include/tr_idp.h include/tr_rp.h \
	include/tr_comm.h include/tr_apc.h \
	include/tr_tid.h include/tr_trp.h \
	include/tr_filter.h \
	include/tid_internal.h

pkgdata_DATA=schema.sql
nobase_dist_pkgdata_DATA=redhat/init redhat/sysconfig redhat/trusts.cfg redhat/tidc-wrapper redhat/trust_router-wrapper redhat/tr-test-main.cfg redhat/default-main.cfg redhat/tids-wrapper redhat/sysconfig.tids

if HAVE_SYSTEMD
systemdsystemunit_DATA = tids.service
endif

EXTRA_DIST = trust_router.spec common/tests.json schema.sql tids.service \
	tr/manual.cfg tr/portal.cfg \
	redhat/tids.init
