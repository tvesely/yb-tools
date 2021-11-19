TOP_BUILDDIR = ../.
include ../global.mk

.PHONEY: all yb-getlogs

all: tools test yb-getlogs

yb-getlogs:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -ldflags=" -X 'github.com/yugabyte/yb-tools/yb-getlogs/cmd.Version=$$(git rev-parse HEAD)'" -o ${TOP_BUILDDIR}/bin/yb-getlogs main.go

