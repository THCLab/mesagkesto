FROM rust:1.73.0 as build

WORKDIR /app
RUN echo '[workspace] \n\
\n\
members = [\n\
    "messagebox",\n\
]' > Cargo.toml
COPY . /app/
RUN cargo fetch
RUN cargo build --release

FROM debian:12-slim
RUN apt update && apt install libssl-dev -y
WORKDIR /app
COPY --from=build /app/target/release/messagebox .
COPY messagebox.yml /app/messagebox.yml
EXPOSE 8081
ENTRYPOINT ["/app/messagebox"]
