FROM rust:latest

RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /usr/src/yaulta
COPY . .
RUN cargo build --release

ENV PATH="/usr/src/yaulta/target/release:${PATH}"

CMD yaulta capture --interface "$CAPTURED_INTERFACE" \
	-s \
	--output-dir /pcap \
	--nats-server "$NATS_MASTER_ADDR" \
	--node-id "$NATS_NODE_ID" \
	--subject "$NATS_SUBJECT"


