PROTOC_CMD = protoc
PROTOC_ARGS = --proto_path=./inapi/ --go_opt=paths=source_relative --go_out=./inapi/ --go-grpc_out=./inapi/ ./inapi/*.proto

HTOML_TAG_FIX_CMD = htoml-tag-fix
HTOML_TAG_FIX_ARGS = inapi/

BUILDCOLOR="\033[34;1m"
BINCOLOR="\033[37;1m"
ENDCOLOR="\033[0m"

ifndef V
	QUIET_BUILD = @printf '%b %b\n' $(BUILDCOLOR)BUILD$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
	QUIET_INSTALL = @printf '%b %b\n' $(BUILDCOLOR)INSTALL$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
endif


all: go-v2
	@echo ""
	@echo "build complete"
	@echo ""

go-v2:
	$(QUIET_BUILD)$(PROTOC_CMD) $(PROTOC_ARGS) $(CCLINK)
	$(QUIET_BUILD)$(HTOML_TAG_FIX_CMD) $(HTOML_TAG_FIX_ARGS) $(CCLINK)

