AC_CONFIG_MACRO_DIR([m4])
AC_PREREQ([2.69])
AC_INIT([liballocs], [0.1], [srk31@cl.cam.ac.uk])
AC_CONFIG_SRCDIR([tools/ifacetypes.cpp])
AC_CONFIG_HEADERS([config.h])
AC_PREFIX_DEFAULT(/usr/local)

CFLAGS="-I$prefix/include $CFLAGS"
CXXFLAGS="-I$prefix/include $CXXFLAGS"
CPPFLAGS="-I$prefix/include $CPPFLAGS"
LDFLAGS="-L$prefix/lib $LDFLAGS"
PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$PKG_CONFIG_PATH"
export CFLAGS CXXFLAGS LDFLAGS PKG_CONFIG_PATH

LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([dlopen])
LTDL_INIT([nonrecursive])
AC_LANG([C++])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wno-portability])
AM_MAINTAINER_MODE
AC_LANG_PUSH([C])
AC_PROG_CC
AC_PROG_CC_C99
AC_LANG_POP([C])

AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11
export CXXFLAGS

AC_C_INLINE
AC_TYPE_SIZE_T
AC_CHECK_TYPES([ptrdiff_t])
AC_PROG_LN_S
AC_PROG_INSTALL

my_save_cflags="$CFLAGS"
CFLAGS="-flto -ffat-lto-objects"
AC_MSG_CHECKING([whether $CC supports -flto -ffat-lto-objects])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [],
    [AC_MSG_FAILURE([need a C compiler that supports -flto (e.g. gcc >= 4.8) Try again with CC=path/to/newer-cc?])]
)
CFLAGS="$my_save_cflags"

OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="-std=c++11 $CPPFLAGS"

AC_CHECK_HEADERS([assert.h cassert cctype cmath cstddef cstdint cstdio cstdlib deque dlfcn.h elf.h], [], [AC_MSG_FAILURE(Failed to find required header)])
AC_CHECK_HEADERS([err.h errno.h fstream iomanip iostream libunwind.h link.h map memory pthread.h search.h], [], [AC_MSG_FAILURE(Failed to find required header)])
AC_CHECK_HEADERS([set sstream stdarg.h stdbool.h stddef.h stdint.h stdio.h stdlib.h string string.h strings.h], [], [AC_MSG_FAILURE(Failed to find required header)])
AC_CHECK_HEADERS([sys/mman.h sys/resource.h sys/stat.h sys/syscall.h sys/time.h sys/types.h unistd.h vector wchar.h], [], [AC_MSG_FAILURE(Failed to find required header)])
AC_CHECK_HEADERS([alloca.h], [], [AC_MSG_FAILURE(Failed to find required header)])
AC_CHECK_HEADERS([libelf.h libelf/libelf.h gelf.h libelf/gelf.h], [], [], [])
AC_CHECK_HEADERS([dwarf.h], [], [AC_MSG_FAILURE(Failed to find required header)])

AX_BOOST_BASE

AC_CHECK_HEADER([boost/regex/concepts.hpp], [], [AC_MSG_FAILURE([boost::regex is required])])
AC_HAVE_LIBRARY(boost_regex, [], [AC_MSG_FAILURE([boost::regex is required])])

CPPFLAGS=$OLD_CPPFLAGS

# If the user (sanely) supplied _CXXFLAGS, and not _CFLAGS, 
# duplicate the latter to the former.  See rant about pkg-config in Makefile.am.
# We save the old _CFLAGS.
USER_LIBCXXFILENO_CFLAGS="$LIBCXXFILENO_CFLAGS"
LIBCXXFILENO_CFLAGS="$LIBCXXFILENO_CXXFLAGS"
USER_LIBDWARFPP_CFLAGS="$LIBDWARFPP_CFLAGS"
LIBDWARFPP_CFLAGS="$LIBDWARFPP_CXXFLAGS"
USER_LIBCXXGEN_CFLAGS="$LIBCXXGEN_CFLAGS"
LIBCXXGEN_CFLAGS="$LIBCXXGEN_CXXFLAGS"
USER_LIBSRK31CXX_CFLAGS="$LIBSRK31CXX_CFLAGS"
LIBSRK31CXX_CFLAGS="$LIBSRK31CXX_CXXFLAGS"
USER_LIBANTLR3CXX_CFLAGS="$LIBANTLR3CXX_CFLAGS"
LIBANTLR3CXX_CFLAGS="$LIBANTLR3CXX_CXXFLAGS"
USER_DWARFIDL_CFLAGS="$DWARFIDL_CFLAGS"
DWARFIDL_CFLAGS="$DWARFIDL_CXXFLAGS"

# Now, all the information from pkg-config or from user _CXXFLAGS) is in _CFLAGS.
# We might also have USER_ _CFLAGS, if the user did what pkg.m4 stupidly told them.
# We use this information (i.e. propagate to _CXXFLAGS) only if the user *didn't* give us
# _CXXFLAGS.
AM_CONDITIONAL(SUPPLIED_LIBCXXFILENO_CFLAGS, [test x"$USER_LIBCXXFILENO_CFLAGS" != x && test x"$LIBCXXFILENO_CXXFLAGS" = x])
AM_CONDITIONAL(SUPPLIED_LIBDWARFPP_CFLAGS, [test x"$USER_LIBDWARFPP_CFLAGS" != x && test x"$LIBDWARFPP_CXXFLAGS" = x])
AM_CONDITIONAL(SUPPLIED_LIBCXXGEN_CFLAGS, [test x"$USER_LIBCXXGEN_CFLAGS" != x && test x"$LIBCXXGEN_CXXFLAGS" = x])
AM_CONDITIONAL(SUPPLIED_LIBSRK31CXX_CFLAGS, [test x"$USER_LIBSRK31CXX_CFLAGS" != x && test x"$LIBSRK31CXX_CXXFLAGS" = x])
AM_CONDITIONAL(SUPPLIED_LIBANTLR3CXX_CFLAGS, [test x"$USER_LIBANTLR3CXX_CFLAGS" != x && test x"$LIBANTLR3CXX_CXXFLAGS" = x])
AM_CONDITIONAL(SUPPLIED_DWARFIDL_CFLAGS, [test x"$USER_DWARFIDL_CFLAGS" != x && test x"$DWARFIDL_CXXFLAGS" = x])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBCXXFILENO], [libcxxfileno])
PKG_CHECK_MODULES([LIBSRK31CXX], [libsrk31cxx])
PKG_CHECK_MODULES([LIBDWARFPP], [libdwarfpp])
PKG_CHECK_MODULES([LIBCXXGEN], [libcxxgen])
PKG_CHECK_MODULES([DWARFIDL], [dwarfidl])
PKG_CHECK_MODULES([LIBANTLR3CXX], [libantlr3cxx])

AC_SUBST(TRAP_SYSCALLS, $TRAP_SYSCALLS)
AC_SUBST(MALLOC_HOOKS, $MALLOC_HOOKS)
AC_SUBST(LIBDLBIND, $LIBDLBIND)
AC_SUBST(LIBRUNT, $LIBRUNT)

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Enable debug mode]))
AC_ARG_ENABLE([real-libunwind], AS_HELP_STRING([--enable-real-libunwind], [Use real libunwind (by default we have our own)]))

AC_ARG_WITH([libsystrap],
            [AS_HELP_STRING([--with-libsystrap=DIR],
              [where to find libsystrap (headers and source)])],
            [
                if test -d "$withval"
                then
                        ac_libsystrap="$withval"
                else
                        AC_MSG_ERROR(--with-libsystrap expected directory name)
                fi
            ],
            [ac_libsystrap=$(realpath $srcdir)/contrib/trap-syscalls/libsystrap])
AC_ARG_WITH([librunt],
            [AS_HELP_STRING([--with-librunt=DIR],
              [where to find librunt (headers and source)])],
            [
                if test -d "$withval"
                then
                        ac_librunt="$withval"
                else
                        AC_MSG_ERROR(--with-librunt expected directory name)
                fi
            ],
            [ac_librunt=$(realpath $srcdir)/contrib/librunt])
AC_ARG_WITH([libmallochooks],
            [AS_HELP_STRING([--with-libmallochooks=DIR],
              [where to find libmallochooks (headers, source, templates)])],
            [
                if test -d "$withval"
                then
                        ac_libmallochooks="$withval"
                else
                        AC_MSG_ERROR(--with-libmallochooks expected directory name)
                fi
            ],
            [ac_libmallochooks=$(realpath $srcdir)/contrib/libmallochooks])
AC_ARG_WITH([libdlbind],
            [AS_HELP_STRING([--with-libdlbind=DIR],
              [where to find libdlbind (headers, source)])],
            [
                if test -d "$withval"
                then
                        ac_libdlbind="$withval"
                else
                        AC_MSG_ERROR(--with-libdlbind expected directory name)
                fi
            ],
            [ac_libdlbind=$(realpath $srcdir)/contrib/libdlbind])

AC_SUBST([libmallochooks], [$ac_libmallochooks])
AC_SUBST([librunt], [$ac_librunt])
AC_SUBST([libsystrap], [$ac_libsystrap])
AC_SUBST([libdlbind], [$ac_libdlbind])
AM_CONDITIONAL(DEBUG, [test "x$enable_debug" = "xyes"])
AM_CONDITIONAL(USE_REAL_LIBUNWIND, [test "x$enable_real-libunwind" = "xyes"])

AC_CONFIG_FILES([Makefile liballocs.pc config.mk])
AC_OUTPUT
