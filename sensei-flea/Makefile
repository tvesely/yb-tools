TOP_BUILDDIR = ../.
include ../global.mk

.PHONEY: all

all: tools test sensei-flea

sensei-flea:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -ldflags=" -X 'github.com/yugabyte/yb-tools/yugaware-client/cmd.Version=$$(git rev-parse HEAD)'" -o ${TOP_BUILDDIR}/bin/sensei-flea main.go

# TODO: move this into a go build directive
codegen: tools
	oapi-codegen --old-config-style --package oapi -generate types hack/sendsafely.openapi.json > ${TOP_BUILDDIR}/pkg/client/sendsafely/oapi/types.gen.go
	oapi-codegen --old-config-style --package oapi -generate client hack/sendsafely.openapi.json > ${TOP_BUILDDIR}/pkg/client/sendsafely/oapi/client.gen.go