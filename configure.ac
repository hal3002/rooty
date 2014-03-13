#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([rooty], [0.1], [https://github.com/linuxgeek247/rooty])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/rooty.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign no-define tar-ustar subdir-objects])

# Pull in the checks for the build tools.
AC_CANONICAL_HOST

AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

# CFLAGS Can go away with its annoying default -g -O2
CFLAGS=''

# Pull in the platform specific build/configure environment options.
extra_incl=
case "$host" in
    *-openbsd*)
        AC_DEFINE([C_BSD],1,[os is OpenBSD])
        LDFLAGS="${LDFLAGS} -L/usr/local/lib -luuid"
        extra_incl="-I/usr/local/include"
        CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
        platform="openbsd"
    ;;
    *-linux*)
        AC_DEFINE([C_LINUX],1,[target is linux])
        AC_DEFINE([Linux],1,[target is linux])
        CDEFINE="-D_GNU_SOURCE"
        CPPFLAGS="${CPPFLAGS} -D_GNU_SOURCE"
        platform="linux"
    ;;
    *-freebsd*)
        AC_DEFINE([C_BSD],1,[os is freebsd])
        LDFLAGS="${LDFLAGS} -L/usr/local/lib -luuid"
        extra_incl="-I/usr/local/include"
        CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
        platform="freebsd"
    ;;
    *-apple*)
        AC_DEFINE(BROKEN_SIOCGIFMTU,,[Define if SIOCGIFMTU unavailable])
        AC_DEFINE([C_BSD],1,[os is OS X])
        e2fs_uuid=yes
        if test -d "/sw"; then
            LDFLAGS="${LDFLAGS} -L/sw/lib"
            extra_incl="-I/sw/include"
            CPPFLAGS="${CPPFLAGS} -I/sw/include"
        fi
        if test -d "/opt/local"; then
            LDFLAGS="${LDFLAGS} -L/opt/local/lib"
            extra_incl="-I/opt/local/include"
            CPPFLAGS="${CPPFLAGS} -I/opt/local/include"
        fi
        LIBTOOL=glibtool
        LIBTOOLIZE=glibtoolize
        CDEFINE="-Ds6_addr32=__u6_addr.__u6_addr32"
        platform="apple"
   ;;
esac

AM_CONDITIONAL([PLATFORM_LINUX], [test x$platform = xlinux])
AM_CONDITIONAL([PLATFORM_FREEBSD], [test x$platform = xfreebsd])

# Pull in the dependancies on on the API (use the nugget way).
AC_CHECK_LIB([pthread], [pthread_create], [], [PTHREAD="no"])
AS_IF([test "x$PTHREAD" = "xno"],
          [AC_MSG_ERROR("pthread library not found")]
     )

AC_CHECK_HEADERS([pcap.h], [], [PCAP_HEADER="no"])
AS_IF([test "x$PCAP_HEADER" = "xno"],
          [AC_MSG_ERROR("pcap header not found")]
     )
AC_CHECK_LIB([pcap], [pcap_open_live], [], [PCAP="no"])
AS_IF([test "x$PCAP" = "xno"],
          [AC_MSG_ERROR("pcap library not found")]
     )

AC_CHECK_HEADERS([hijack.h], [], [HIJACK_HEADER="no"])
AS_IF([test "x$HIJACK_HEADER" = "xno"],
          [AC_MSG_ERROR("hijack header not found")]
     )

AC_CHECK_LIB([hijack], [InitHijack], [], [HIJACK="no"])
AS_IF([test "x$HIJACK" = "xno"],
          [AC_MSG_ERROR("hijack library not found")]
     )

# Pull in the standard header and function checks.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h stdarg.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINTPTR_T
AC_TYPE_INTPTR_T
AC_TYPE_INTMAX_T
AC_TYPE_UINTMAX_T
AC_CHECK_TYPES([size_t])
AC_CHECK_TYPES([ssize_t])
AC_CHECK_TYPES([uint16_t])
AC_CHECK_TYPES([uint32_t])
AC_CHECK_TYPES([uint8_t])
AC_CHECK_TYPES([uintptr_t])
AC_CHECK_TYPES([intptr_t])
AC_CHECK_TYPES([intmax_t])
AC_CHECK_TYPES([uintmax_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([inet_ntoa memset munmap socket strdup strerror strncasecmp strstr strtoul])


AC_CHECK_HEADERS([sys/endian.h], [], [SYS_ENDIAN_HEADER="no"]) 
# Pull in the compiler customisation options for different compilers.
ICC=no
if eval "echo $CC|grep icc >/dev/null" ; then
    if eval "$CC -help |grep libcxa >/dev/null" ; then
        CFLAGS="$CFLAGS -ip -static-libcxa"
        XCCFLAGS="-XCClinker -static-libcxa"
    else
        CFLAGS="$CFLAGS -ip -static-intel"
        XCCFLAGS="-XCClinker -static-intel"
    fi
    if test "$COPT" = "-O2" ; then
        COPT="-O3"
    fi
    CWARNINGS="-wd869"
    ICC=yes
    GCC=no
fi

if test "$GCC" = yes ; then
    if test "x$enable_debug" = "xyes"; then
        CFLAGS="-ggdb $CFLAGS"
    else
        CFLAGS="-O2 $CFLAGS"
    fi

    if test "x$enable_profile" = "xyes"; then
        LDFLAGS="$LDFLAGS -XCClinker -pg"
    fi

    CFLAGS="$CFLAGS -std=c99 -fno-strict-aliasing"
    CPPFLAGS="$CPPFLAGS -fno-strict-aliasing"
    CWARNINGS="$CWARNINGS -Wall -Werror -Wwrite-strings -Wformat -fdiagnostics-show-option -Wextra -Wformat-security -Wsign-compare -Wcast-align -Wno-unused-parameter"
    if test "x$NOT_PEDANTIC" = "x"; then
        CWARNINGS="$CWARNINGS -pedantic"
    fi
    echo $CFLAGS
fi

# Pull in the standard compiler and linker flags.
CFLAGS="$CFLAGS $CWARNINGS"
LDFLAGS="$LDFLAGS $PROFILE_LDFLAGS -static"

echo "LDFLAGS set to $LDFLAGS"
echo "CFLAGS set to $CFLAGS"
AC_SUBST(XCCFLAGS)
AC_SUBST(LIBS)
AC_SUBST(extra_incl)

AC_CONFIG_FILES([ \
Makefile \
src/Makefile \
])
AC_OUTPUT

