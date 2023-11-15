FROM openpolicyagent/opa:0.56.0-static
COPY ./policies /var/opa/roots
WORKDIR /var/opa/roots

CMD [ "run", \
        "--server", \
        "--addr", ":8181", \
        "--bundle", ".", \
        "--authorization", "basic" \
    ]

EXPOSE 8181
