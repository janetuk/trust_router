# Rudimentary CMakeLists.txt
#
# This is not used for real builds, it mostly exists to enable code navigation in
# CLion. Real builds use autotools + make.
#
cmake_minimum_required(VERSION 3.6)
project(trust_router)

set(CMAKE_CXX_STANDARD 11)

include(FindPkgConfig)
pkg_check_modules(GLIB glib-2.0 REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS})

include_directories(include)

set(SOURCE_FILES
        common/tests/cfg_test.c
        common/tests/commtest.c
    common/tests/dh_test.c
    common/tests/mq_test.c
    common/tests/thread_test.c
    common/jansson_iterators.h
    common/t_constraint.c
    common/tr_apc.c
    common/tr_comm.c
    common/tr_config.c
    common/tr_constraint.c
    common/tr_debug.c
    common/tr_dh.c
    common/tr_filter.c
        common/tr_gss_names.c
    common/tr_idp.c
    common/tr_mq.c
    common/tr_msg.c
    common/tr_name.c
    common/tr_rp.c
    common/tr_util.c
    gsscon/test/gsscon_client.c
    gsscon/test/gsscon_server.c
    gsscon/gsscon_active.c
    gsscon/gsscon_common.c
    gsscon/gsscon_passive.c
    include/trust_router/tid.h
    include/trust_router/tr_constraint.h
    include/trust_router/tr_dh.h
    include/trust_router/tr_name.h
    include/trust_router/tr_versioning.h
    include/trust_router/trp.h
    include/gsscon.h
    include/tid_internal.h
    include/tr.h
    include/tr_apc.h
    include/tr_cfgwatch.h
    include/tr_comm.h
    include/tr_config.h
    include/tr_debug.h
    include/tr_event.h
    include/tr_filter.h
        include/tr_gss_names.h
    include/tr_idp.h
    include/tr_mq.h
    include/tr_msg.h
    include/tr_rp.h
    include/tr_tid.h
    include/tr_trp.h
    include/tr_util.h
    include/trp_internal.h
    include/trp_ptable.h
    include/trp_rtable.h
    tid/example/tidc_main.c
    tid/example/tids_main.c
    tid/tid_req.c
    tid/tid_resp.c
    tid/tidc.c
    tid/tids.c
    tr/tr.c
    tr/tr_cfgwatch.c
    tr/tr_event.c
    tr/tr_main.c
    tr/tr_tid.c
    tr/tr_trp.c
    tr/trpc_main.c
    trp/test/ptbl_test.c
    trp/test/rtbl_test.c
    trp/msgtst.c
    trp/trp_conn.c
    trp/trp_ptable.c
    trp/trp_req.c
    trp/trp_rtable.c
    trp/trp_upd.c
    trp/trpc.c
    trp/trps.c include/tr_name_internal.h mon/mon_req.c mon/mon_req_encode.c mon/mon_req_decode.c
        mon/mon_resp.c mon/mon_common.c mon/mon_resp_encode.c tr/tr_mon.c mon/mons.c include/tr_socket.h)

# Does not actually build!
add_executable(trust_router ${SOURCE_FILES})

# Test build targets - for debugging
add_executable(test_mon_req_encode mon/mon_common.c mon/mon_req.c mon/tests/test_mon_req_encode.c mon/mon_req_encode.c)
target_link_libraries(test_mon_req_encode jansson talloc glib-2.0)

add_executable(test_mon_req_decode mon/mon_common.c mon/mon_req.c mon/tests/test_mon_req_decode.c mon/mon_req_decode.c)
target_link_libraries(test_mon_req_decode jansson talloc glib-2.0)

add_executable(test_mon_resp_encode mon/mon_common.c mon/mon_req.c mon/mon_resp.c mon/mon_resp_encode.c common/tr_name.c mon/tests/test_mon_resp_encode.c)
target_link_libraries(test_mon_resp_encode jansson talloc glib-2.0)
