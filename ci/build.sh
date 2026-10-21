#!/bin/sh
#
# Build an nginx that carries this module.  The CI workflows run this:
#
#     ci/build.sh 1.30.5 /tmp/nginx-test
#     TEST_NGINX_BINARY=/tmp/nginx-test/sbin/nginx prove -r t/
#
# usage: ci/build.sh <nginx version> <install prefix> [mode]
#
#     static    the module built into the binary (the default)
#     dynamic   the module built as a loadable object
#
# CC picks the compiler, which also picks the warnings nginx turns on: its
# clang set holds -Wconditional-uninitialized, which gcc has no equivalent
# for, and it is an error there.
#
# nginx lands in $CI_WORK, ./ci-work by default, and is reused on a
# second run.  A warning from this module's own source fails the build.

set -eu

NGINX=${1:?nginx version missing}
PREFIX=${2:?install prefix missing}
MODE=${3:-static}

SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}
JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)

# Every version and digest comes from one file, so a local run pins what a
# CI run pins.  Not overridable from the environment: a version and its
# digest have to move together.
PINS=$SRC/.github/versions.env
[ -r "$PINS" ] || {
	echo "ci/build.sh: cannot read $PINS" >&2
	exit 1
}
# shellcheck source=../.github/versions.env
. "$PINS"

mkdir -p "$WORK"

tarball=$WORK/nginx-$NGINX.tar.gz
url=https://nginx.org/download/nginx-$NGINX.tar.gz

# The digest is looked up by version, so building another release means
# adding its pin first.  A missing pin fails the build instead of being
# waved through.
key=NGINX_$(echo "$NGINX" | tr . _)_SHA256
eval "want=\${$key:-}"
if [ -z "$want" ]; then
	echo "ci/build.sh: no sha256 for nginx $NGINX in $PINS" >&2
	echo "ci/build.sh: harvest one with" >&2
	echo "    ci/fetch-verify.sh $url - $tarball" >&2
	exit 1
fi

"$SRC/ci/fetch-verify.sh" "$url" "$want" "$tarball"

rm -rf "$WORK/nginx-$NGINX"
tar xzf "$tarball" -C "$WORK"

case $MODE in
static)
	how=--add-module
	;;
dynamic)
	how=--add-dynamic-module
	;;
*)
	echo "ci/build.sh: unknown mode \"$MODE\"" >&2
	exit 2
	;;
esac

cd "$WORK/nginx-$NGINX"

# On FreeBSD the OpenLDAP client comes from the ports tree and lands under
# /usr/local, which the compiler does not search by itself.  The README says
# to point at it with these two flags, so this does, and a build there needs
# nothing from the caller.
if [ "$(uname -s)" = FreeBSD ]; then
	CI_CC_OPT="${CI_CC_OPT:+$CI_CC_OPT }-I/usr/local/include"
	CI_LD_OPT="${CI_LD_OPT:+$CI_LD_OPT }-L/usr/local/lib"
fi

# the sanitizer workflow builds through this script as well, so that
# there is one build path and not two that drift apart
set --
if [ -n "${CI_CC_OPT:-}" ]; then
	set -- "$@" --with-cc-opt="$CI_CC_OPT"
fi
if [ -n "${CI_LD_OPT:-}" ]; then
	set -- "$@" --with-ld-opt="$CI_LD_OPT"
fi

if [ -n "${CC:-}" ]; then
	set -- "$@" --with-cc="$CC"
fi

echo "== configure ($MODE)"
# --with-http_ssl_module is required, and not for the test suite: the
# module's own ldaps:// support is compiled only when nginx was configured
# with OpenSSL, and without it "url ldaps://..." is refused at startup.
./configure --prefix="$PREFIX" --with-debug --with-http_ssl_module \
	"$how=$SRC" "$@" > "$WORK/configure-$NGINX.log" 2>&1 ||
	{ tail -30 "$WORK/configure-$NGINX.log"; exit 1; }

echo "== make -j$JOBS"
make -j"$JOBS" > "$WORK/make-$NGINX.log" 2>&1 ||
	{ tail -40 "$WORK/make-$NGINX.log"; exit 1; }

if grep -E "ngx_http_auth_ldap_module\.c.*warning" "$WORK/make-$NGINX.log"; then
	echo "ci/build.sh: the compiler warned about this module, see above" >&2
	exit 1
fi

make install > /dev/null
"$PREFIX/sbin/nginx" -v
