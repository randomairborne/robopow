FROM rust:alpine AS builder

WORKDIR /build
COPY . .

RUN apk add musl-dev
RUN cargo build --release

FROM alpine

COPY --from=builder /build/target/release/robopow /usr/bin/robopow

EXPOSE 8080

CMD [ "/usr/bin/robopow" ]
