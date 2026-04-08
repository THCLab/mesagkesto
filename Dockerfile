FROM rust:1.91 AS build

WORKDIR /app

# 1. Create the workspace structure first
RUN echo '[workspace]\nmembers = ["messagebox"]' > Cargo.toml

# 2. Copy ONLY the Cargo manifests first (to cache dependencies)
# Adjust 'messagebox' if your crate folder has a different name
COPY messagebox/Cargo.toml ./messagebox/Cargo.toml

# 3. Fetch dependencies (This layer is cached unless Cargo.toml changes)
RUN cargo fetch

# 4. Copy the rest of the source code (excluding target/ thanks to .dockerignore)
COPY . /app/

# 5. Build the release binary
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:12-slim

# Install only runtime dependencies
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the binary
COPY --from=build /app/target/release/messagebox .

EXPOSE 8081
ENTRYPOINT ["/app/messagebox"]
