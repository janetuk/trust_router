ACLOCAL_AMFLAGS = -I m4
DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
bin_PROGRAMS= tr/trust_router tr/trpc tid/example/tidc tid/example/tids common/tests/tr_dh_test common/tests/mq_test \
              common/tests/thread_test trp/msgtst trp/test/rtbl_test trp/test/ptbl_test common/tests/cfg_test \
              common/tests/commtest common/tests/name_test common/tests/filt_test mon/tests/test_mon_req_encode \
              mon/tests/test_mon_req_decode mon/tests/test_mon_resp_encode tr/trmon
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
	common/tr_gss_names.c \
	common/tr_socket.c \
	$(mon_srcs)

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
common/tr_config.c \
common/tr_config_internal.c \
common/tr_mq.c

# general monitoring message sources
mon_srcs =                   \
    mon/mon_common.c         \
    mon/mon_req.c            \
    mon/mon_req_encode.c     \
    mon/mon_req_decode.c     \
    mon/mon_resp.c           \
    mon/mon_resp_decode.c    \
    mon/mon_resp_encode.c

# monitoring server sources
mons_srcs = \
    mon/mons.c \
    mon/mons_handlers.c

check_PROGRAMS = common/t_constraint
TESTS = common/t_constraint
TEST_CFLAGS = -Wno-missing-prototypes

lib_LTLIBRARIES = libtr_tid.la

libtr_tid_la_SOURCES = $(tid_srcs) \
$(common_srcs) \
trp/trp_req.c \
trp/trp_upd.c

libtr_tid_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden
libtr_tid_la_LIBADD = gsscon/libgsscon.la $(GLIB_LIBS)
libtr_tid_la_LDFLAGS = $(AM_LDFLAGS) -version-info 4:1:2 -no-undefined

common_t_constraint_SOURCES = common/t_constraint.c \
common/tr_debug.c \
common/tr_name.c \
common/tr_constraint.c \
common/tr_dh.c \
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
tr/tr_mon.c \
common/tr_gss.c \
common/tr_gss_client.c \
$(tid_srcs) \
$(trp_srcs) \
$(common_srcs) \
$(mons_srcs)

tr_trust_router_LDFLAGS = $(AM_LDFLAGS) -levent_pthreads -pthread
tr_trust_router_LDADD = gsscon/libgsscon.la $(GLIB_LIBS)

tr_trpc_SOURCES =tr/trpc_main.c \
tr/tr_trp.c \
common/tr_gss.c \
common/tr_gss_client.c \
$(trp_srcs) \
$(tid_srcs) \
$(common_srcs)

tr_trpc_LDADD = gsscon/libgsscon.la $(GLIB_LIBS)
tr_trpc_LDFLAGS = $(AM_LDFLAGS) -pthread

tr_trmon_SOURCES = tr/trmon_main.c \
common/tr_gss.c \
common/tr_gss_client.c \
$(tid_srcs) \
$(trp_srcs) \
$(common_srcs) \
mon/monc.c

tr_trmon_LDADD = gsscon/libgsscon.la  $(GLIB_LIBS)
tr_trmon_LDFLAGS = $(AM_LDFLAGS) -pthread

trp_msgtst_SOURCES = trp/msgtst.c \
$(common_srcs) \
trp/trp_req.c \
trp/trp_upd.c \
tid/tid_resp.c \
tid/tid_req.c
trp_msgtst_LDADD =  $(GLIB_LIBS)

trp_test_rtbl_test_SOURCES = trp/test/rtbl_test.c \
common/tr_name.c \
common/tr_gss_names.c \
common/tr_debug.c \
trp/trp_rtable.c
trp_test_rtbl_test_LDADD =  $(GLIB_LIBS)

trp_test_ptbl_test_SOURCES = trp/test/ptbl_test.c \
common/tr_gss.c \
common/tr_gss_client.c \
$(tid_srcs) \
$(trp_srcs) \
$(common_srcs)
trp_test_ptbl_test_LDADD = gsscon/libgsscon.la $(GLIB_LIBS)
trp_test_ptbl_test_LDFLAGS = $(AM_LDFLAGS) -pthread

tid_example_tidc_SOURCES = tid/example/tidc_main.c \
common/tr_gss.c \
common/tr_gss_client.c \
$(tid_srcs) \
$(trp_srcs) \
$(common_srcs)
tid_example_tidc_LDADD = gsscon/libgsscon.la  $(GLIB_LIBS)
tid_example_tidc_LDFLAGS = $(AM_LDFLAGS) -pthread

tid_example_tids_SOURCES = tid/example/tids_main.c \
common/tr_gss.c \
common/tr_gss_client.c \
$(tid_srcs) \
$(trp_srcs) \
$(common_srcs)
tid_example_tids_LDADD = gsscon/libgsscon.la  $(GLIB_LIBS)
tid_example_tids_LDFLAGS = $(AM_LDFLAGS) -pthread

common_tests_tr_dh_test_SOURCES = common/tr_dh.c \
common/tr_debug.c \
common/tests/dh_test.c

common_tests_mq_test_SOURCES = common/tr_mq.c \
common/tests/mq_test.c \
common/tr_debug.c

common_tests_mq_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc -pthread

common_tests_cfg_test_SOURCES = common/tests/cfg_test.c \
$(common_srcs) \
common/tr_gss.c \
common/tr_gss_client.c \
$(tid_srcs) \
$(trp_srcs)
common_tests_cfg_test_LDADD = gsscon/libgsscon.la  $(GLIB_LIBS)
common_tests_cfg_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc -pthread

common_tests_thread_test_SOURCES = common/tr_mq.c \
common/tr_debug.c \
common/tests/thread_test.c

common_tests_commtest_SOURCES = common/tests/commtest.c \
$(common_srcs) \
common/tr_gss.c \
common/tr_gss_client.c \
$(tid_srcs) \
$(trp_srcs)
common_tests_commtest_LDADD = gsscon/libgsscon.la $(GLIB_LIBS)
common_tests_commtest_LDFLAGS = $(AM_LDFLAGS) -ltalloc -pthread

common_tests_thread_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc -pthread

common_tests_name_test_SOURCES = common/tests/name_test.c \
              $(common_srcs) \
              common/tr_gss.c \
              common/tr_gss_client.c \
              $(tid_srcs) \
              $(trp_srcs)
common_tests_name_test_LDADD = gsscon/libgsscon.la $(GLIB_LIBS)
common_tests_name_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc -pthread
common_tests_name_test_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS)

common_tests_filt_test_SOURCES = common/tests/filt_test.c \
              $(common_srcs) \
              common/tr_gss.c \
              common/tr_gss_client.c \
              $(tid_srcs) \
              $(trp_srcs)
common_tests_filt_test_LDADD = gsscon/libgsscon.la $(GLIB_LIBS)
common_tests_filt_test_LDFLAGS = $(AM_LDFLAGS) -ltalloc -pthread
common_tests_filt_test_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS)

mon_tests_test_mon_req_encode_SOURCES = mon/tests/test_mon_req_encode.c \
    $(mon_srcs) \
    common/tr_name.c
mon_tests_test_mon_req_encode_LDADD = $(GLIB_LIBS)
mon_tests_test_mon_req_encode_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS)

mon_tests_test_mon_req_decode_SOURCES = mon/tests/test_mon_req_decode.c \
    $(mon_srcs) \
    common/tr_name.c
mon_tests_test_mon_req_decode_LDADD = $(GLIB_LIBS)
mon_tests_test_mon_req_decode_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS)

mon_tests_test_mon_resp_encode_SOURCES = mon/tests/test_mon_resp_encode.c \
    $(mon_srcs) \
    common/tr_name.c
mon_tests_test_mon_resp_encode_LDADD = $(GLIB_LIBS)
mon_tests_test_mon_resp_encode_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS)

pkginclude_HEADERS = include/trust_router/tid.h include/trust_router/tr_name.h \
	include/tr_debug.h include/trust_router/trp.h \
	include/trust_router/tr_dh.h \
	include/trust_router/tr_constraint.h \
	include/trust_router/tr_versioning.h 

noinst_HEADERS = include/gsscon.h include/tr_config.h \
	include/tr_msg.h include/tr.h \
	include/tr_idp.h include/tr_rp.h \
	include/tr_comm.h include/tr_apc.h \
	include/tr_tid.h include/tr_trp.h include/tr_mon.h \
	include/tr_filter.h include/tr_gss_names.h \
	include/tid_internal.h include/trp_internal.h \
	include/tr_cfgwatch.h include/tr_event.h \
	include/tr_mq.h include/trp_ptable.h \
	include/trp_rtable.h include/tr_util.h \
	include/tr_name_internal.h include/tr_gss.h

pkgdata_DATA=schema.sql
nobase_dist_pkgdata_DATA=redhat/init redhat/sysconfig redhat/organizations.cfg redhat/tidc-wrapper redhat/trust_router-wrapper redhat/tr-test-internal.cfg redhat/default-internal.cfg redhat/tids-wrapper redhat/sysconfig.tids

if HAVE_SYSTEMD
systemdsystemunit_DATA = tids.service
endif

EXTRA_DIST = trust_router.spec common/tests.json schema.sql tids.service \
	tr/internal.cfg tr/organizations.cfg \
	redhat/tids.init
