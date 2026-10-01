#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
state_root=$(mktemp -d "${TMPDIR:-/tmp}/mihomo-patched-deps.XXXXXX")
modfile="$state_root/mihomo.mod"

cp "$repo_root/go.mod" "$modfile"
cp "$repo_root/go.sum" "$state_root/mihomo.sum"

apply_module_patches() {
	module=$1
	patch_dir=$2
	name=$3

	go mod download "$module"
	module_dir=$(go list -m -f '{{.Dir}}' "$module")
	patched_dir="$state_root/$name"

	if [ -z "$module_dir" ] || [ ! -d "$module_dir" ]; then
		echo "unable to locate module: $module" >&2
		exit 1
	fi

	mkdir -p "$patched_dir"
	cp -R "$module_dir/." "$patched_dir/"
	chmod -R u+w "$patched_dir"
	git -C "$patched_dir" init -q
	for patch in "$patch_dir"/*.patch; do
		[ -e "$patch" ] || continue
		if ! git -C "$patched_dir" apply --check --whitespace=error-all "$patch"; then
			echo "dependency patch does not apply: $patch" >&2
			exit 1
		fi
		git -C "$patched_dir" apply --whitespace=error-all "$patch"
	done
	if [ -d "$patch_dir/_files" ]; then
		cp -R "$patch_dir/_files/." "$patched_dir/"
	fi

	go mod edit -modfile="$modfile" -replace="$module=$patched_dir"
}

apply_module_patches \
	github.com/metacubex/quic-go \
	"$repo_root/patches/quic-go" \
	quic-go

apply_module_patches \
	github.com/metacubex/sing-quic \
	"$repo_root/patches/sing-quic" \
	sing-quic

apply_module_patches \
	github.com/metacubex/sing-tun \
	"$repo_root/patches/sing-tun" \
	sing-tun

if [ "$#" -gt 0 ]; then
	printf 'GOFLAGS=-modfile=%s\n' "$modfile" >> "$1"
else
	printf 'GOFLAGS=-modfile=%s\n' "$modfile"
fi
