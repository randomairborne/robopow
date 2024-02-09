FROM alpine AS client-builder

RUN apk add zstd brotli pigz

COPY /*.js /assets/

RUN find /assets/ -type f -exec pigz -k9 '{}' \; -exec pigz -zk9 '{}' \; -exec brotli -k9 '{}' \; -exec zstd -qk19 '{}' \;

FROM rust:alpine AS builder

WORKDIR /build
COPY . .

RUN apk add musl-dev
RUN cargo build --release

FROM alpine

COPY --from=builder /build/target/release/robopow /usr/bin/robopow
COPY --from=client-builder /assets/robopow.js /var/www/robopow/robopow.js

EXPOSE 8080
WORKDIR /var/www/robopow

ENTRYPOINT "/usr/bin/robopow"
