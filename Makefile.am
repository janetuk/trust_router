bin_PROGRAMS= tr/tr tid/example/tidc tid/example/tids common/dh_test/dh_test
AM_CPPFLAGS=-I$(srcdir)/include
SUBDIRS = gsscon 

tr_tr_SOURCES = tr/tr_main.c \
tid/tidc.c \
tid/tids.c \
common/tr_name.c \
common/tr_msg.c \
common/tr_dh.c \
common/tr_config.c 

tr_tr_LDADD = gsscon/libgsscon.la

tid_example_tidc_SOURCES = tid/example/tidc_main.c \
tid/tidc.c \
common/tr_name.c \
common/tr_msg.c \
common/tr_dh.c

tid_example_tidc_LDADD = gsscon/libgsscon.la

tid_example_tids_SOURCES = tid/example/tids_main.c \
tid/tids.c \
common/tr_name.c \
common/tr_msg.c \
common/tr_dh.c

tid_example_tids_LDADD = gsscon/libgsscon.la

common_dh_test_dh_test_SOURCES = common/tr_dh.c \
common/dh_test/dh_test.c

