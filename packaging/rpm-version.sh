#!/bin/sh
# Translate a git describe into an RPM Version and Release.
#
# RPM versions may not contain '-', and an untagged build has to sort BELOW
# the release it is heading for rather than above it -- otherwise a developer
# RPM shadows the next real one and `yum update` will not replace it.
#
#   v1.2.3              -> 1.2.3      1
#   v1.2.3-5-gabc1234   -> 1.2.3      0.5.gabc1234
#   v1.2.3-5-gabc1234-dirty -> 1.2.3  0.5.gabc1234.dirty
#   (no tags) abc1234   -> 0.0.0      0.abc1234
#
# A release starting with 0. sorts before 1, which is the convention for
# snapshots taken after a tag (see the Fedora packaging guidelines).
set -eu

describe="${1:-}"
if [ -z "${describe}" ]; then
	describe="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
fi

# Strip a leading v, then split the tag from anything git appended.
v="${describe#v}"

case "${v}" in
*-*)
	tag="${v%%-*}"
	rest="${v#*-}"
	# Everything after the tag becomes part of the release, with the
	# separators RPM allows.
	release="0.$(echo "${rest}" | tr '-' '.')"
	;;
*)
	tag="${v}"
	release="1"
	;;
esac

# An untagged repository gives a bare commit (or "dev"), which is not a
# version at all; call it 0.0.0 so the RPM is still well-formed and obviously
# not a release.
case "${tag}" in
'' | *[!0-9.]*)
	release="0.$(echo "${v}" | tr '-' '.')"
	tag="0.0.0"
	;;
esac

echo "${tag} ${release}"
