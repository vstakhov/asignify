AC_PREREQ(2.59)
AC_INIT(asignify, 1.0)

AC_CANONICAL_SYSTEM

ASIGNIFY_LIBRARY_VERSION=1:0:0
#                        | | |
#                 +------+ | +---+
#                 |        |     |
#              current:revision:age
#                 |        |     |
#                 |        |     +- increment if interfaces have been added
#                 |        |        set to zero if interfaces have been removed
#                 |        |        or changed
#                 |        +- increment if source code has changed
#                 |           set to zero if current is incremented
#                 +- increment if interfaces have been added, removed or changed
AC_SUBST(ASIGNIFY_LIBRARY_VERSION)

AM_INIT_AUTOMAKE([1.11 foreign -Wno-portability no-dist-gzip dist-xz])
AM_SILENT_RULES([yes])

dnl Initialize Libtool
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC_C99
AX_CFLAGS_WARN_ALL
AM_PROG_CC_C_O 
AC_C_CONST
AC_TYPE_SIZE_T
AC_CHECK_FUNCS(memmove bcopy)
AC_PROG_LN_S

AC_CHECK_HEADERS_ONCE([stdlib.h])
AC_CHECK_HEADERS_ONCE([stddef.h])
AC_CHECK_HEADERS_ONCE([stdarg.h])
AC_CHECK_HEADERS_ONCE([stdbool.h])
AC_CHECK_HEADERS_ONCE([stdint.h])
AC_CHECK_HEADERS_ONCE([string.h])
AC_CHECK_HEADERS_ONCE([unistd.h])
AC_CHECK_HEADERS_ONCE([readpassphrase.h])

dnl BSD library on Linux systems
AC_CANONICAL_HOST
case $host_os in
  linux*)
        OS_CFLAGS="-D_XOPEN_SOURCE -D_GNU_SOURCE"
        OS_LDFLAGS=""
        OS_LIBS="-ldl -lrt -lbsd"
        ;;
    *)
        OS_CFLAGS="-D_BSD_SOURCE -D_WITH_GETLINE"
        OS_LDFLAGS=
        OS_LIBS=
        ;;
esac
AC_SUBST(OS_CFLAGS)
AC_SUBST(OS_LDFLAGS)
AC_SUBST(OS_LIBS)
AC_CHECK_HEADERS_ONCE([bsd/stdlib.h])
AC_CHECK_HEADERS_ONCE([bsd/string.h])
AC_CHECK_HEADERS_ONCE([bsd/stdio.h])
AC_CHECK_HEADERS_ONCE([bsd/readpassphrase.h])
AC_CHECK_HEADERS_ONCE([bsd/libutil.h])
AC_CHECK_HEADERS_ONCE([bsd/err.h])

AC_CHECK_DECL([O_NOFOLLOW],
        AC_DEFINE([HAVE_O_NOFOLLOW], [1], [Use O_NOFOLLOW for open]),
        [],
        [#include <sys/types.h>
         #include <sys/stat.h>
         #include <fcntl.h>
     	]
)

AC_CHECK_FUNCS([explicit_bzero memset_s])
AC_MSG_CHECKING(if weak symbols are supported)
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
		__attribute__((weak)) void __dummy(void *x) { }
		void f(void *x) { __dummy(x); }
		]], [[ ]]
	)],
	[AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_WEAK_SYMBOLS], [1], [weak symbols are supported])],
	[AC_MSG_RESULT(no)])

AC_CHECK_FUNCS([posix_memalign aligned_alloc valloc])

dnl Capsicum support
AC_CHECK_HEADERS_ONCE([sys/capability.h])
AC_CHECK_HEADERS_ONCE([sys/capsicum.h])
AC_CHECK_LIB(c, cap_sandboxed, [
   AC_DEFINE(HAVE_CAPSICUM, 1, [Define 1 if you have 'capsicum'.])
])

AC_CACHE_CHECK(for arc4random_uniform,
               ac_cv_func_arc4random_uniform,
               [AC_TRY_COMPILE([#include <stdlib.h>],
                               [arc4random_uniform(255);],
                               [ac_cv_func_arc4random_uniform=yes],
                               [ac_cv_func_arc4random_uniform=no])])
if test "$ac_cv_func_arc4random_uniform" = yes ; then
	AC_DEFINE(HAVE_ARC4RANDOM, 1, [Define 1 if you have 'arc4random_uniform' function.])
fi

AC_ARG_ENABLE([openssl],
    AS_HELP_STRING([--enable-openssl], [Use openssl for faster hashes computation]))
AS_IF([test "x$enable_openssl" = "xyes"],
	[AX_CHECK_OPENSSL([
		AC_DEFINE(HAVE_OPENSSL, 1, [Define 1 if you have openssl.])], []
	)]
)

dnl Check if Libtool is present
dnl Libtool is used for building share libraries 
AC_PROG_LIBTOOL

AC_CONFIG_FILES(Makefile
                src/Makefile
                libasignify/Makefile
                include/Makefile)
AC_CONFIG_HEADERS(config.h)
AC_OUTPUT