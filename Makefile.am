bin_PROGRAMS= tr/tr tpq/example/tpqc tpq/example/tpqs tidr/example/tidrc tidr/example/tidrs
AM_CPPFLAGS=-I$(srcdir)/include
SUBDIRS = gsscon 

tr_tr_SOURCES = tr/tr_main.c \
tpq/tpqs.c \
common/tr_name.c \
common/tr_msg.c \
common/tr_config.c 

tr_tr_LDADD = gsscon/libgsscon.la

tpq_example_tpqc_SOURCES = tpq/example/tpqc_main.c \
tpq/tpqc.c \
common/tr_name.c \
common/tr_msg.c \
common/tr_dh.c

tpq_example_tpqc_LDADD = gsscon/libgsscon.la

tpq_example_tpqs_SOURCES = tpq/example/tpqs_main.c \
tpq/tpqs.c \
common/tr_name.c \
common/tr_msg.c

tpq_example_tpqs_LDADD = gsscon/libgsscon.la

tidr_example_tidrc_SOURCES = tidr/example/tidrc_main.c \
tidr/tidrc.c \
common/tr_name.c \
common/tr_msg.c

tidr_example_tidrc_LDADD = gsscon/libgsscon.la

tidr_example_tidrs_SOURCES = tidr/example/tidrs_main.c \
tidr/tidrs.c \
common/tr_name.c \
common/tr_msg.c

tidr_example_tidrs_LDADD = gsscon/libgsscon.la


