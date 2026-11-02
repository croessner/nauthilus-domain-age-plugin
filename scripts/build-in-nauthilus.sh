#!/bin/sh
# Build domain-age.so inside a pristine Nauthilus core tree at CORE_REF.
#
# Runs inside golang:<GO_VERSION>-alpine<ALPINE_VERSION> with the core
# repository mounted read-only at /core, this repository at /plugin and the
# output directory at /out.
set -eu

: "${CORE_REF:?CORE_REF is required}"
: "${ARTIFACT:?ARTIFACT is required}"
: "${BUNDLE_COMMIT:?BUNDLE_COMMIT is required}"
: "${BUNDLE_BUILD_TIME:?BUNDLE_BUILD_TIME is required}"
GO_TAGS="${GO_TAGS:-netgo}"
export GOEXPERIMENT="${GOEXPERIMENT:-runtimesecret}"

apk add --no-cache build-base git rsync >/dev/null

core_dir="$(mktemp -d)"
trap 'rm -rf "$core_dir"' EXIT

git config --global --add safe.directory /core
git config --global --add safe.directory /plugin
git clone --quiet --no-hardlinks /core "$core_dir"
git -C "$core_dir" checkout --quiet --detach "${CORE_REF}"

cd "$core_dir"

# The builder toolchain must be the exact toolchain pinned by the core release.
core_toolchain="$(awk '$1 == "toolchain" { print $2 }' go.mod)"
builder_toolchain="$(go env GOVERSION)"
if [ -n "$core_toolchain" ] && [ "$core_toolchain" != "$builder_toolchain" ]; then
	echo "builder toolchain $builder_toolchain does not match core toolchain $core_toolchain" >&2
	exit 1
fi

# External plugins attest the unmodified release host before adding private sources.
native_flags=$(go run -mod=vendor ./scripts/native_artifact_fingerprint -tags="${GO_TAGS}")

# Replace any historical in-core copy of the plugin with this repository.
plugin_path="contrib/plugins/domain-age"
rm -rf "${core_dir:?}/${plugin_path}"
mkdir -p "$core_dir/$plugin_path"
rsync -a \
	--exclude .git \
	--exclude build \
	--exclude docs \
	--exclude examples \
	--exclude scripts \
	--exclude testdata \
	--exclude go.mod \
	--exclude go.sum \
	--exclude '*_test.go' \
	--exclude '*.md' \
	--exclude '*.yml' \
	--exclude '*.json' \
	/plugin/ "$core_dir/$plugin_path/"

# Include external-only packages from existing pinned module versions.
go mod vendor

core_commit="$(git -C /core rev-parse "${CORE_REF}^{commit}")"

GOOS=linux \
GOARCH=amd64 \
CGO_ENABLED=1 \
go build \
	-mod=vendor \
	-tags="${GO_TAGS}" \
	-buildmode=plugin \
	-trimpath \
	-ldflags="${native_flags} -X main.buildCommit=${BUNDLE_COMMIT} -X main.buildTime=${BUNDLE_BUILD_TIME} -X main.buildTags=${GO_TAGS}" \
	-o "/out/${ARTIFACT}" \
	"./${plugin_path}"

# Verify both the declared host identity and the actual Go shared-package ABI.
go build -mod=vendor -tags="${GO_TAGS}" -trimpath \
	-ldflags="${native_flags}" -o /tmp/native-bundle-check ./server/pluginloader/testdata/nativebundle
/tmp/native-bundle-check "/out/${ARTIFACT}"

sha256sum "/out/${ARTIFACT}"
printf 'bundle_commit=%s\nbundle_build_time=%s\ncore_commit=%s\ncore_ref=%s\ngo_version=%s\ngoexperiment=%s\nbuild_tags=%s\nbuild_flags=%s\n' \
	"${BUNDLE_COMMIT}" \
	"${BUNDLE_BUILD_TIME}" \
	"${core_commit}" \
	"${CORE_REF}" \
	"$(go env GOVERSION)" \
	"${GOEXPERIMENT}" \
	"${GO_TAGS}" \
	"-mod=vendor -tags=${GO_TAGS} -buildmode=plugin -trimpath" \
	> "/out/${ARTIFACT}.provenance"
