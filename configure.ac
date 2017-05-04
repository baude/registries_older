AC_INIT([registries], [0.1])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([registries.c])

AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Check for C compiler
AC_PROG_CC
AC_CONFIG_FILES([Makefile])

PKG_PROG_PKG_CONFIG
AC_OUTPUT
#AC_SEARCH_LIBS(yaml, glib-2.0, json-glib-1.0, gio-2.0, gobject-2.0)
PKG_CHECK_MODULES([GLIB], [glib-2.0], [have_libglib=yes], [have_libglib=no])
AM_CONDITIONAL([GLIB],  [test "$have_libglib" = "yes"])

PKG_CHECK_MODULES([yaml], [yaml-0.1], [have_libyaml=yes], [have_libyaml=no])
AM_CONDITIONAL([yaml],  [test "$have_libyaml" = "yes"])

PKG_CHECK_MODULES([json_glib], [json-glib-1.0], [have_libjson_glib=yes], [have_libjson_glib=no])
AM_CONDITIONAL([json_glib],  [test "$have_libjson_glib" = "yes"])

PKG_CHECK_MODULES([gio], [gio-2.0], [have_libgio=yes], [have_libhgio=no])
AM_CONDITIONAL([gio],  [test "$have_libgio" = "yes"])

PKG_CHECK_MODULES([gobject], [gobject-2.0], [have_libgobject=yes], [have_libgobject=no])
AM_CONDITIONAL([gobject],  [test "$have_libgobject" = "yes"])

#AM_CFLAGS = -I/usr/include/json-glib-1.0 -I/usr/include -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include
#AC_SUBST(FOO_CFLAGS)
