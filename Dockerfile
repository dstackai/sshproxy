FROM gcr.io/distroless/static-debian13

COPY build/dstack-sshproxy /dstack-sshproxy

ENTRYPOINT ["/dstack-sshproxy"]
