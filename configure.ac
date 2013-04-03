AC_PREREQ(2.63)
AC_INIT([trust_router],[0.0.1],
[bugs@project-moonshot.org])
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_AUX_DIR(build-aux)
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
AM_MAINTAINER_MODE
LT_INIT()

AC_PROG_CC
AC_PROG_RANLIB

AC_CHECK_LIB([gssapi_krb5], [gss_init_sec_context])
AC_CHECK_LIB([com_err], [error_message])
AC_CHECK_LIB([jansson], [json_object])
AC_CHECK_LIB([crypto], [DH_new])
AC_CHECK_HEADERS(gssapi.h gssapi_ext.h jansson.h openssl/dh.h openssl/bn.h)
AC_CONFIG_FILES([Makefile gsscon/Makefile])
AC_OUTPUT
