# openpolicyagent/opa:0.56.0
FROM openpolicyagent/opa@sha256:80c895c2bc7db38ad93aa3773903ea12ba641020a8bccde83c6ad50a7f2a5e73
COPY ./policies /var/opa/roots
WORKDIR /var/opa/roots

CMD [ "run", \
        "--server", \
        "--addr", ":8181", \
        "--bundle", ".", \
        "--authorization", "basic" \
    ]

EXPOSE 8181