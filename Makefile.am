bin_PROGRAMS= tr/tr tpq/tpqc tpq/tpqs
AM_CPPFLAGS=-I$(srcdir)/include
SUBDIRS = gsscon 

tr_tr_SOURCES = tr/tr_main.c \
tpq/tpqs.c \
tpq/tpq_common.c \
common/tr_config.c

tr_tr_LDADD = gsscon/libgsscon.la

tpq_tpqc_SOURCES = tpq/example/tpqc_main.c \
tpq/tpqc.c \
tpq/tpq_common.c

tpq_tpqc_LDADD = gsscon/libgsscon.la

tpq_tpqs_SOURCES = tpq/example/tpqs_main.c \
tpq/tpqs.c \
tpq/tpq_common.c

tpq_tpqs_LDADD = gsscon/libgsscon.la


