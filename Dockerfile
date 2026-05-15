FROM alpine:3.20 AS builder

RUN apk add --no-cache gcc make musl-dev libmicrohttpd-dev jansson-dev

WORKDIR /build
COPY main.c Makefile ./

RUN make


FROM alpine:3.20

RUN apk add --no-cache libmicrohttpd jansson stress-ng

COPY --from=builder /build/sysmontress /usr/local/bin/sysmontress

EXPOSE 8080

CMD ["sysmontress"]
