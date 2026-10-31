# Image de cocon-api : compilation en deux étapes, exécution sans shell ni
# privilèges (distroless). Voir deploy/ pour la mise en service.

FROM rust:1-bookworm AS build
WORKDIR /src

# Dépendances d'abord : elles restent en cache tant que Cargo.lock ne change pas.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/cocon_api* target/release/cocon-api

COPY src src
COPY web web
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/cocon-api /usr/local/bin/cocon-api
USER nonroot
# Derrière le proxy HTTPS de Coolify (ou tout proxy sur le réseau Docker).
# DATABASE_URL est à fournir au lancement.
ENV COCON_API_BIND=0.0.0.0:8787 \
    COCON_API_BEHIND_PROXY=true \
    COCON_API_SIGNUP=invite
EXPOSE 8787
ENTRYPOINT ["cocon-api"]
CMD ["serve"]
