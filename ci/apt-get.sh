#!/bin/sh
#
# apt-get with a bound and two more tries.
#
# A mirror that accepted the connection and then stopped answering held six
# jobs of one run until GitHub's six hour ceiling killed them, 360 and 361
# minutes for the two that were measured, and the run produced no verdict.
#
# A step inside a composite action cannot carry timeout-minutes, so the
# bound lives here.  Worst case it gives up after 3 * 180 + 2 * 5 = 550
# seconds, inside the 15 minutes every job carries.  In its own file so
# there is one implementation and so the lint gate sees it, which it cannot
# do for a run block in a workflow.
#
# usage: ci/apt-get.sh update -qq
#        ci/apt-get.sh install -y --no-install-recommends foo bar

set -eu

[ "$#" -gt 0 ] || { echo "usage: $0 <apt-get arguments>" >&2; exit 2; }

attempt=1

while :; do
	# DEBIAN_FRONTEND through env(1) and not sudo -E: whether sudo may
	# preserve the environment depends on the runner's sudoers.
	if timeout 180 sudo env DEBIAN_FRONTEND=noninteractive \
			apt-get -o DPkg::Lock::Timeout=60 "$@"; then
		exit 0
	fi

	if [ "$attempt" -ge 3 ]; then
		echo "apt-get $1 failed three times, giving up" >&2
		exit 1
	fi

	echo "apt-get $1 failed, retrying ($attempt of 3)" >&2
	attempt=$((attempt + 1))
	sleep 5
done
