# domain-age native Nauthilus plugin.
#
# Go plugins require the exact host package identity, so every compile, test,
# vet and lint run happens inside a clean clone of the Nauthilus core at
# CORE_REF with this repository copied to contrib/plugins/domain-age.

# Development actions reset the same exact-core checkout and must run serially.
.NOTPARALLEL:

GO ?= go
GO_VERSION ?= 1.27.3
ALPINE_VERSION ?= 3.24
CORE_REPO ?= $(HOME)/GoLandProjects/nauthilus
CORE_REF ?= 774ca996838aafd379b2557719914ff5d724a5aa
GOEXPERIMENT ?= runtimesecret
GO_TAGS ?= netgo
GOLANGCI_LINT ?= golangci-lint
ARTIFACT ?= domain-age.so
BUILD_DIR ?= $(CURDIR)/build
CORE_WORKDIR ?= $(BUILD_DIR)/core
BUNDLE_COMMIT ?= $(shell git -C $(CURDIR) rev-parse HEAD)
BUNDLE_BUILD_TIME ?= $(shell git -C $(CURDIR) show -s --format=%cI $(BUNDLE_COMMIT))
SIGNING_KEY ?=
IMAGE ?= ghcr.io/croessner/nauthilus-domain-age-plugin
IMAGE_TAG ?= $(CORE_REF)-$(shell git -C $(CURDIR) rev-parse --short HEAD)
ALLOW_DIRTY ?= 0

export GOEXPERIMENT

IN_CORE = CORE_REPO="$(abspath $(CORE_REPO))" CORE_REF="$(CORE_REF)" CORE_WORKDIR="$(CORE_WORKDIR)" \
	PLUGIN_DIR="$(CURDIR)" GO="$(GO)" GO_TAGS="$(GO_TAGS)" GOLANGCI_LINT="$(GOLANGCI_LINT)" \
	sh $(CURDIR)/scripts/in-nauthilus.sh

.PHONY: all check test vet lint fmt-check test-docker build checksum sign image verify clean

all: check build

## check: formatting, vet, lint and race tests inside the CORE_REF tree.
check: fmt-check vet lint test

## test: run race tests and reference activation checks inside the CORE_REF tree.
test:
	$(IN_CORE) test

## vet: go vet inside the CORE_REF tree.
vet:
	$(IN_CORE) vet

## lint: golangci-lint with the core configuration inside the CORE_REF tree.
lint:
	$(IN_CORE) lint

## fmt-check: fail when gofmt would change any tracked Go file.
fmt-check:
	$(IN_CORE) fmt-check

## test-docker: the race tests with the exact release builder toolchain image.
test-docker:
	docker run --rm --platform linux/amd64 \
		-v "$(abspath $(CORE_REPO)):/core:ro" \
		-v "$(CURDIR):/plugin:ro" \
		-e CORE_REPO=/core -e CORE_REF="$(CORE_REF)" -e PLUGIN_DIR=/plugin \
		-e CORE_WORKDIR=/tmp/core -e GOEXPERIMENT="$(GOEXPERIMENT)" -e GO_TAGS="$(GO_TAGS)" \
		-e INSTALL_PACKAGES=1 \
		golang:$(GO_VERSION)-alpine$(ALPINE_VERSION) \
		sh /plugin/scripts/in-nauthilus.sh test

## build: compile, ABI-check and record provenance for the Linux shared object.
build:
	@test "$(ALLOW_DIRTY)" = 1 || test -z "$$(git -C $(CURDIR) status --porcelain)" || \
		(echo "worktree is dirty; commit first or set ALLOW_DIRTY=1" >&2; exit 1)
	mkdir -p "$(BUILD_DIR)"
	docker run --rm --platform linux/amd64 \
		-v "$(abspath $(CORE_REPO)):/core:ro" \
		-v "$(CURDIR):/plugin:ro" \
		-v "$(BUILD_DIR):/out" \
		-e CORE_REF="$(CORE_REF)" \
		-e GOEXPERIMENT="$(GOEXPERIMENT)" \
		-e GO_TAGS="$(GO_TAGS)" \
		-e ARTIFACT="$(ARTIFACT)" \
		-e BUNDLE_COMMIT="$(BUNDLE_COMMIT)" \
		-e BUNDLE_BUILD_TIME="$(BUNDLE_BUILD_TIME)" \
		golang:$(GO_VERSION)-alpine$(ALPINE_VERSION) \
		sh /plugin/scripts/build-in-nauthilus.sh

## checksum: build and write the SHA-256 file next to the artifact.
checksum: build
	cd "$(BUILD_DIR)" && sha256sum "$(ARTIFACT)" > "$(ARTIFACT).sha256"

## verify: re-check the recorded checksum of an existing artifact.
verify:
	cd "$(BUILD_DIR)" && sha256sum -c "$(ARTIFACT).sha256"

## sign: detached minisign signature with the core signing tool (key never printed).
sign: checksum
	@test -s "$(SIGNING_KEY)" || (echo "SIGNING_KEY is missing" >&2; exit 1)
	@ARTIFACT_PATH="$(BUILD_DIR)/$(ARTIFACT)" SIGNING_KEY="$(SIGNING_KEY)" $(IN_CORE) sign
	chmod 0644 "$(BUILD_DIR)/$(ARTIFACT).minisig"

## image: package an already signed artifact set into a minimal carrier image.
image:
	@test -s "$(BUILD_DIR)/$(ARTIFACT)" || (echo "signed artifact is missing; run make sign first" >&2; exit 1)
	@test -s "$(BUILD_DIR)/$(ARTIFACT).minisig" || (echo "artifact signature is missing; run make sign first" >&2; exit 1)
	@test -s "$(BUILD_DIR)/$(ARTIFACT).sha256" || (echo "artifact checksum is missing; run make sign first" >&2; exit 1)
	@test -s "$(BUILD_DIR)/$(ARTIFACT).provenance" || (echo "artifact provenance is missing; run make sign first" >&2; exit 1)
	docker build --platform linux/amd64 \
		-f Dockerfile.artifact \
		-t "$(IMAGE):$(IMAGE_TAG)" \
		--build-arg ARTIFACT="$(ARTIFACT)" \
		.

clean:
	rm -rf "$(BUILD_DIR)"

.PHONY: guardrails
guardrails: check

## import: validate and optionally atomically install a normalized provider snapshot.
.PHONY: import
import:
	@INPUT="$(INPUT)" OUTPUT="$(OUTPUT)" $(IN_CORE) import

## govulncheck: analyze the exact-core plugin package using the installed vulnerability checker.
.PHONY: govulncheck release-guardrails
govulncheck:
	$(IN_CORE) govulncheck

## release-guardrails: verify source, dependency vulnerabilities and native host ABI before publishing.
release-guardrails: guardrails govulncheck build
