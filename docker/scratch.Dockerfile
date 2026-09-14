# syntax=docker/dockerfile:1
FROM scratch

COPY --chmod=755 app /bin/app
COPY config.toml /config.toml

# The gateway's local reload socket needs /tmp even in a scratch image.
WORKDIR /tmp
WORKDIR /

ENTRYPOINT ["/bin/app"]
CMD ["--config", "/config.toml"]
