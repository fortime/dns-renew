FROM docker.io/library/rust:1.82.0 AS builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Create an empty src directory to trick Cargo into thinking it's a valid Rust project
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build the dependencies without the actual source code to cache dependencies separately
RUN cargo build --release

# Now copy the source code
COPY ./src ./src

# Build your application
RUN touch -a -m src/main.rs \
        && cargo build --release

# Start a new stage to create a smaller image without unnecessary build dependencies
FROM debian:bookworm-slim

# Set the working directory
WORKDIR /usr/src/app

RUN apt update \
        && apt install -y --no-install-recommends libssl3 openssl ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Init config file
RUN mkdir -p conf/name-conf.d/ \
        && mkdir -p state \
        && echo "name_conf_dir = \"$(pwd)/conf/name-conf.d/\"" > conf/dns-renew.toml \
        && echo "name_state_dir = \"$(pwd)/state/\"" >> conf/dns-renew.toml \
        && echo "\n[update_credentials]" >> conf/dns-renew.toml

# Copy the built binary from the previous stage
COPY --from=builder /usr/src/app/target/release/dns-renew ./

# Command to run the application
ENTRYPOINT ["./dns-renew"]

CMD ["-c", "conf/dns-renew.toml"]
