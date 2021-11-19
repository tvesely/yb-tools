include global.mk

YBTOOLS = yb-getlogs ycrc yugatool yugaware-client

all: ${YBTOOLS}

.PHONY: ${YBTOOLS}
${YBTOOLS}:
	${MAKE} -C $@

clean:
	rm -rf bin/
	rm -rf out/
