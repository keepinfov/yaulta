FROM rust:latest

RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /usr/src/yaulta
COPY . .
RUN cargo build --release

ENV PATH="/usr/src/yaulta/target/release:${PATH}"

CMD yaulta capture -i "$CAPTURED_INTERFACE"


