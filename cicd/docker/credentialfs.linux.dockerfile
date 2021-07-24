ARG MATRIX_ARCH

FROM ghcr.io/arhat-dev/builder-golang:1.16-alpine as builder

ARG MATRIX_ARCH

COPY . /app
RUN dukkha golang local build credentialfs \
    -m kernel=linux -m arch=${MATRIX_ARCH}

FROM scratch

LABEL org.opencontainers.image.source https://github.com/arhat-dev/credentialfs

ARG MATRIX_ARCH
# we may need to access http endpoint, so include these tls ca-certs
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder \
    "/app/build/credentialfs.linux.${MATRIX_ARCH}" \
    /credentialfs

ENV PATH=/
ENTRYPOINT [ "/credentialfs" ]
