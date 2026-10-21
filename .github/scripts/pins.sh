#!/bin/sh
#
# Hand the pins in .github/versions.env to a workflow as job outputs:
#
#     .github/scripts/pins.sh >> "$GITHUB_OUTPUT"
#
#     nginx=["1.28.3","1.30.5",...]   for a strategy.matrix through fromJSON
#     version=1.30.5                  for the jobs that build one release
#
# A matrix is read before any step of its own job runs, so the list cannot
# be produced inside that job; it has to arrive as the output of an earlier
# one.  Everywhere else a step sources .github/versions.env directly.

set -eu

ENVFILE=$(dirname "$0")/../versions.env

[ -r "$ENVFILE" ] || {
	echo "pins.sh: cannot read $ENVFILE" >&2
	exit 1
}

# The file is written to be sourced, so a value holding more than one word
# carries quotes.  Sourcing it here would mean running it, so the values are
# read out and the quotes stripped.
versions=$(sed -n 's/^NGINX_VERSIONS=//p' "$ENVFILE" | tr -d '"')
version=$(sed -n 's/^NGINX_VERSION=//p' "$ENVFILE" | tr -d '"')

[ -n "$versions" ] || { echo "pins.sh: NGINX_VERSIONS is not set in $ENVFILE" >&2; exit 1; }
[ -n "$version" ] || { echo "pins.sh: NGINX_VERSION is not set in $ENVFILE" >&2; exit 1; }

printf 'nginx=['
sep=
for v in $versions; do
	printf '%s"%s"' "$sep" "$v"
	sep=,
done
printf ']\n'

printf 'version=%s\n' "$version"
