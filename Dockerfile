# openpolicyagent/opa:0.26.0
FROM openpolicyagent/opa@sha256:194124d6a0ef36a3f5fbf70aa5e84460969b2cb6fb1652d0c7016b8711c75519
COPY ./policies /var/opa/roots
WORKDIR /var/opa/roots

CMD [ "run", \
        "--server", \
        "--addr", ":8181", \
        "--bundle", ".", \
        "--authorization", "basic" \
    ]

EXPOSE 8181