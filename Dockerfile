FROM rust:1.91 AS build

WORKDIR /app

# 1. Create the workspace manifest
RUN echo '[workspace]\nmembers = ["messagebox"]' > Cargo.toml

# 2. Copy the Cargo.toml of the member crate
COPY messagebox/Cargo.toml ./messagebox/Cargo.toml

# 3. Copy the source code of the member crate (CRITICAL STEP)
# This ensures Cargo sees the src/ directory and valid targets
COPY messagebox/src ./messagebox/src

# 4. Now fetch dependencies
# Cargo can now parse the manifest successfully because src/ exists
RUN cargo fetch

# 5. Copy the rest of the project (other crates, root files, etc.)
COPY . /app/

# 6. Build
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:12-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/messagebox .
EXPOSE 8081
ENTRYPOINT ["/app/messagebox"]
