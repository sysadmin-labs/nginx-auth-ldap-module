#!/bin/sh
#
# fetch-verify.sh <url> <sha256|-> <file>
#
# Download <url> to <file> and refuse it unless its sha256 matches.  A
# changed archive, a truncated download or a build cache someone else filled
# fails here instead of being compiled.
#
# A <file> that is already here is not downloaded again, but it IS hashed
# again, so a warm cache that no longer matches is caught as well.  A file
# that fails the check is removed, so the next run cannot pick it up.
#
# With "-" in place of the digest nothing is verified and the digest is
# printed instead.  That is how a new pin is harvested for
# .github/versions.env.  It is a separate, explicit mode and never a
# fallback: a check that quietly turns itself off is worse than no check,
# because it still looks like one.

set -eu

url=${1:?usage: fetch-verify.sh <url> <sha256|-> <file>}
want=${2:?expected sha256 missing, pass - to harvest one}
out=${3:?output file missing}

# sha256sum is in the base system on FreeBSD and on Linux and prints the same
# shape on both; shasum is what macOS carries.  sha256 is the older FreeBSD
# spelling, kept last so the common path is tried first.
digest() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum > /dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        sha256 -q "$1"
    fi
}

# curl is a package on FreeBSD, fetch is in the base system.  A stalled
# server must not hold a runner open, hence the timeouts.
download() {
    if command -v curl > /dev/null 2>&1; then
        curl -sSfL --retry 3 --retry-delay 2 \
            --connect-timeout 30 --max-time 600 -o "$1" "$2"
    else
        fetch -q -o "$1" "$2"
    fi
}

mismatch() {
    echo "fetch-verify.sh: $url does not match its pin" >&2
    echo "  expected $want" >&2
    echo "  got      $1" >&2
    rm -f "$out"
    exit 1
}

if [ -s "$out" ]; then
    got=$(digest "$out")
    if [ "$want" = - ]; then
        echo "$got"
        exit 0
    fi
    [ "$got" = "$want" ] && exit 0
    echo "fetch-verify.sh: $out was already here and did not match, fetching again" >&2
    rm -f "$out"
fi

download "$out" "$url"
got=$(digest "$out")

if [ "$want" = - ]; then
    echo "$got"
    exit 0
fi

[ "$got" = "$want" ] || mismatch "$got"
