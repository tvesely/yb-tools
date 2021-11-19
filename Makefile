include global.mk

YBTOOLS = getlogs ycrc yugatool yugaware-client

all: ${YBTOOLS}

.PHONY: ${YBTOOLS}
${YBTOOLS}:
	${MAKE} -C $@

clean:
	rm -rf bin/
	rm -rf out/
