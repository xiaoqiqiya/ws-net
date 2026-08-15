# syntax=docker/dockerfile:1
FROM scratch

COPY --chmod=755 app /bin/app
COPY config.toml /config.toml

ENTRYPOINT ["/bin/app"]
CMD ["--config", "/config.toml"]
