#!/bin/sh
# $Id: $
# the list of commands that need to run before we do a compile
libtoolize --automake --copy
aclocal -I m4
autoheader
automake --add-missing --copy
autoconf
