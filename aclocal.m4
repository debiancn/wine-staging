dnl Macros used to build the Wine configure script
dnl
dnl Copyright 2002 Alexandre Julliard
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
dnl
dnl As a special exception to the GNU Lesser General Public License,
dnl if you distribute this file as part of a program that contains a
dnl configuration script generated by Autoconf, you may include it
dnl under the same distribution terms that you use for the rest of
dnl that program.

dnl **** Get the ldd program name; used by WINE_GET_SONAME ****
dnl
dnl Usage: WINE_PATH_LDD
dnl
AC_DEFUN([WINE_PATH_LDD],[AC_PATH_PROG(LDD,ldd,true,/sbin:/usr/sbin:$PATH)])

dnl **** Extract the soname of a library ****
dnl
dnl Usage: WINE_GET_SONAME(LIBRARY, FUNCTION, [OTHER_LIBRARIES])
dnl
AC_DEFUN([WINE_GET_SONAME],
[AC_REQUIRE([WINE_PATH_LDD])dnl
AS_VAR_PUSHDEF([ac_Lib],[ac_cv_lib_soname_$1])dnl
AC_CACHE_CHECK([for -l$1 soname], ac_Lib,
[ac_get_soname_save_LIBS=$LIBS
LIBS="-l$1 $3 $LIBS"
  AC_LINK_IFELSE([AC_LANG_CALL([], [$2])],
  [case "$LIBEXT" in
    dylib) AS_VAR_SET(ac_Lib,[`otool -L conftest$ac_exeext | grep lib$1\\.[[0-9A-Za-z.]]*dylib | sed -e "s/^.*\/\(lib$1\.[[0-9A-Za-z.]]*dylib\).*$/\1/"';2,$d'`]) ;;
    so) AS_VAR_SET(ac_Lib,[`$ac_cv_path_LDD conftest$ac_exeext | grep lib$1\\.so | sed -e "s/^.*\(lib$1\.so[[^	 ]]*\).*$/\1/"';2,$d'`]) ;;
  esac
  if test "x$ac_Lib" = "x"
  then
     AS_VAR_SET(ac_Lib,"lib$1.$LIBEXT")
  fi],
  [AS_VAR_SET(ac_Lib,"lib$1.$LIBEXT")])
  LIBS=$ac_get_soname_save_LIBS])
AS_VAR_SET_IF(ac_Lib,[AC_DEFINE_UNQUOTED(AS_TR_CPP(SONAME_LIB$1),["]AS_VAR_GET(ac_Lib)["],
                        [Define to the soname of the lib$1 library.])])dnl
AS_VAR_POPDEF([ac_Lib])])

dnl **** Link C code with an assembly file ****
dnl
dnl Usage: WINE_TRY_ASM_LINK(asm-code,includes,function,[action-if-found,[action-if-not-found]])
dnl
AC_DEFUN([WINE_TRY_ASM_LINK],
[AC_LINK_IFELSE(AC_LANG_PROGRAM([[$2]],[[asm($1); $3]]),[$4],[$5])])

dnl **** Check if we can link an empty program with special CFLAGS ****
dnl
dnl Usage: WINE_TRY_CFLAGS(flags,[action-if-yes,[action-if-no]])
dnl
dnl The default action-if-yes is to append the flags to EXTRACFLAGS.
dnl
AC_DEFUN([WINE_TRY_CFLAGS],
[AS_VAR_PUSHDEF([ac_var], ac_cv_cflags_[[$1]])dnl
AC_CACHE_CHECK([whether the compiler supports $1], ac_var,
[ac_wine_try_cflags_saved=$CFLAGS
CFLAGS="$CFLAGS $1"
AC_LINK_IFELSE(AC_LANG_PROGRAM(), [AS_VAR_SET(ac_var,yes)], [AS_VAR_SET(ac_var,no)])
CFLAGS=$ac_wine_try_cflags_saved])
AS_IF([test AS_VAR_GET(ac_var) = yes],
      [m4_default([$2], [EXTRACFLAGS="$EXTRACFLAGS $1"])], [$3])dnl
AS_VAR_POPDEF([ac_var])])

dnl **** Check if we can link an empty shared lib (no main) with special CFLAGS ****
dnl
dnl Usage: WINE_TRY_SHLIB_FLAGS(flags,[action-if-yes,[action-if-no]])
dnl
AC_DEFUN([WINE_TRY_SHLIB_FLAGS],
[ac_wine_try_cflags_saved=$CFLAGS
CFLAGS="$CFLAGS $1"
AC_LINK_IFELSE([void myfunc() {}],[$2],[$3])
CFLAGS=$ac_wine_try_cflags_saved])

dnl **** Check whether we need to define a symbol on the compiler command line ****
dnl
dnl Usage: WINE_CHECK_DEFINE(name),[action-if-yes,[action-if-no]])
dnl
AC_DEFUN([WINE_CHECK_DEFINE],
[AS_VAR_PUSHDEF([ac_var],[ac_cv_cpp_def_$1])dnl
AC_CACHE_CHECK([whether we need to define $1],ac_var,
    AC_EGREP_CPP(yes,[#ifndef $1
yes
#endif],
    [AS_VAR_SET(ac_var,yes)],[AS_VAR_SET(ac_var,no)]))
AS_IF([test AS_VAR_GET(ac_var) = yes],
      [CFLAGS="$CFLAGS -D$1"
  LINTFLAGS="$LINTFLAGS -D$1"])dnl
AS_VAR_POPDEF([ac_var])])

dnl **** Check for functions with some extra libraries ****
dnl
dnl Usage: WINE_CHECK_LIB_FUNCS(funcs,libs,[action-if-found,[action-if-not-found]])
dnl
AC_DEFUN([WINE_CHECK_LIB_FUNCS],
[ac_wine_check_funcs_save_LIBS="$LIBS"
LIBS="$LIBS $2"
AC_CHECK_FUNCS([$1],[$3],[$4])
LIBS="$ac_wine_check_funcs_save_LIBS"])

dnl **** Check for ln ****
dnl
dnl Usage: WINE_PROG_LN
dnl
AC_DEFUN([WINE_PROG_LN],
[AC_MSG_CHECKING([whether ln works])
rm -f conf$$ conf$$.file
echo >conf$$.file
if ln conf$$.file conf$$ 2>/dev/null; then
  AC_SUBST(LN,ln)
  AC_MSG_RESULT([yes])
else
  AC_SUBST(LN,["cp -p"])
  AC_MSG_RESULT([no, using $LN])
fi
rm -f conf$$ conf$$.file])

dnl **** Check for a mingw program, trying the various mingw prefixes ****
dnl
dnl Usage: WINE_CHECK_MINGW_PROG(variable,prog,[value-if-not-found],[path])
dnl
AC_DEFUN([WINE_CHECK_MINGW_PROG],
[AC_CHECK_PROGS([$1],
   m4_foreach([ac_wine_prefix],
              [i586-mingw32msvc, i386-mingw32msvc, i386-mingw32, mingw32, mingw],
              [ac_wine_prefix-$2 ]),
   [$3],[$4])])


dnl **** Create nonexistent directories from config.status ****
dnl
dnl Usage: WINE_CONFIG_EXTRA_DIR(dirname)
dnl
AC_DEFUN([WINE_CONFIG_EXTRA_DIR],
[AC_CONFIG_COMMANDS([$1],[test -d "$1" || (AC_MSG_NOTICE([creating $1]) && mkdir "$1")])])
