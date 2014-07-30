AC_PREREQ(2.63)
AC_INIT([trust_router],[1.3],
[bugs@project-moonshot.org])
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_AUX_DIR(build-aux)
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([1.11 foreign subdir-objects])
AM_SILENT_RULES
AM_MAINTAINER_MODE
LT_INIT()

AC_PROG_CC
           PKG_PROG_PKG_CONFIG
           AC_ARG_WITH([systemdsystemunitdir],
                   AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
                   [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
           if test "x$with_systemdsystemunitdir" != xno; then
                   AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
           fi
           AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])

AC_CHECK_LIB([gssapi_krb5], [gss_init_sec_context])
AC_CHECK_LIB([com_err], [error_message])
AC_CHECK_LIB(talloc, talloc_asprintf,,
[AC_MSG_ERROR([Please install talloc development])])
AC_CHECK_LIB([sqlite3], [sqlite3_open],,
    [AC_MSG_ERROR([Please install sqlite3 development])])

AC_CHECK_LIB([jansson], [json_object])
AC_CHECK_LIB([crypto], [DH_new])
AC_CHECK_HEADERS(gssapi.h gssapi_ext.h jansson.h openssl/dh.h openssl/bn.h)
AC_CONFIG_FILES([Makefile gsscon/Makefile])
AC_OUTPUT
