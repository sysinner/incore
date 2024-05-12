PROTOC_CMD = protoc
PROTOC_ARGS = --proto_path=./api --go_opt=paths=source_relative --go_out=./inapi --go-grpc_out=./inapi ./api/*.proto
PROTOC_RUST_ARGS = --proto_path=./api --rust_out=experimental-codegen=enabled,kernel=cpp:./inapi ./api/*.proto

HTOML_TAG_FIX_CMD = htoml-tag-fix
HTOML_TAG_FIX_ARGS = ./inapi

BUILDCOLOR="\033[34;1m"
BINCOLOR="\033[37;1m"
ENDCOLOR="\033[0m"

##  RUNC_IMAGE=sysinner/incore-build:0.1
##  RUNC_PLATFORM=--platform=linux/amd64
##
##  RUNC_OK=$(docker images -q "${RUNC_IMAGE}" 2 >/dev/null)

ifndef V
	QUIET_BUILD = @printf '%b %b\n' $(BUILDCOLOR)BUILD$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
	QUIET_INSTALL = @printf '%b %b\n' $(BUILDCOLOR)INSTALL$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
endif

.PHONY: api
api:
	$(QUIET_BUILD)$(PROTOC_CMD) $(PROTOC_ARGS) $(CCLINK)
	# $(QUIET_BUILD)$(PROTOC_CMD) $(PROTOC_RUST_ARGS) $(CCLINK)
	$(QUIET_BUILD)$(HTOML_TAG_FIX_CMD) $(HTOML_TAG_FIX_ARGS) $(CCLINK)

.PHONY: api-in-runc
api-in-runc:
	./build/build-runc.sh
	## docker run --rm -it ${RUNC_PLATFORM} --user "$(shell id -u):$(shell id -g)" -v $(PWD):/build_path -w /build_path ${RUNC_IMAGE}

all: api
	@echo ""
	@echo "build complete"
	@echo ""

