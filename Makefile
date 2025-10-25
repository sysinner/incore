PROTOC_CMD = protoc
PROTOC_ARGS = --proto_path=./api --go_opt=paths=source_relative --go_out=./inapi --go-grpc_out=./inapi ./api/*.proto
PROTOC_RUST_ARGS = --proto_path=./api --rust_out=experimental-codegen=enabled,kernel=cpp:./inapi ./api/*.proto

PROTOC_V2_ARGS = --proto_path=./api/inapi/v2 --go_opt=paths=source_relative --go_out=./v2/inapi --go-grpc_out=./v2/inapi ./api/inapi/v2/*.proto

HTOML_TAG_FIX_CMD = htoml-tag-fix
HTOML_TAG_FIX_ARGS = ./inapi

LYNKAPI_FILTER_CMD = lynkapi-fitter
LYNKAPI_FILTER_V2_ARGS = v2/inapi

##  RUNC_IMAGE=sysinner/incore-build:0.1
##  RUNC_PLATFORM=--platform=linux/amd64
##
##  RUNC_OK=$(docker images -q "${RUNC_IMAGE}" 2 >/dev/null)

.PHONY: api
api:
	$(PROTOC_CMD) $(PROTOC_ARGS)
	$(PROTOC_CMD) $(PROTOC_V2_ARGS)
	# $(PROTOC_CMD) $(PROTOC_RUST_ARGS)
	$(HTOML_TAG_FIX_CMD) $(HTOML_TAG_FIX_ARGS)
	$(LYNKAPI_FILTER_CMD) $(LYNKAPI_FILTER_V2_ARGS)

.PHONY: api-in-runc
api-in-runc:
	./build/build-runc.sh
	## docker run --rm -it ${RUNC_PLATFORM} --user "$(shell id -u):$(shell id -g)" -v $(PWD):/build_path -w /build_path ${RUNC_IMAGE}

all: api
	@echo ""
	@echo "build complete"
	@echo ""

