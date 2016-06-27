#!/bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcidr=.

cd $srcdir
DIE=0

test -f src/init.c || {
	echo
	echo "You must run this script in the top-level hyperint drectory."
	echo
	DIE=1
}

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to generate the hyperinit."
	echo
	DIE=1
}

(autoheader --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoheader installed to generate the hypernit."
	echo
	DIE=1
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have automake installed to generate the hypernit."
	echo
	DIE=1
}
(autoreconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoreconf installed to generate the hypernit."
	echo
	DIE=1
}

if test "$DIE" -eq 1; then
	exit 1
fi

echo
echo "Generating build-system with:"
echo "  aclocal:  $(aclocal --version | head -1)"
echo "  autoconf:  $(autoconf --version | head -1)"
echo "  autoheader:  $(autoheader --version | head -1)"
echo "  automake:  $(automake --version | head -1)"
echo

rm -rf autom4te.cache

aclocal
autoconf
autoheader
automake --add-missing

if [ "$1"x != "musl"x ]; then
	echo
	echo "type '$srcdir/configure' and 'make' to compile hyperstart."
	echo
	exit 0
fi

topdir=`pwd`
rm -rf build/musl
tar -xf build/musl.tar.gz -C build/

sed 's#muslpath#'"$topdir"'/build/musl/#g' build/musl/lib/musl-gcc.specs.temp > build/musl/lib/musl-gcc.specs

cat > build/musl/bin/musl-gcc << EOF
#!/bin/sh
exec "\${REALGCC:-gcc}" "\$@" -specs "$topdir/build/musl/lib/musl-gcc.specs"
EOF
chmod a+x build/musl/bin/musl-gcc

echo
echo "type 'CC="$topdir"/build/musl/bin/musl-gcc $srcdir/configure --with-musl --host=x86_64-none-linux' and 'make' to compile hyperstart."
echo
