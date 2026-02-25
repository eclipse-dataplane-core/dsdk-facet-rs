# Dockerfile for E2E test binary
# This container runs the vault-test binary to verify HashicorpVaultClient

FROM alpine:latest

# Copy the pre-built binary
COPY vault-test /usr/local/bin/vault-test

# Make it executable
RUN chmod +x /usr/local/bin/vault-test

# Run the test binary on container start
ENTRYPOINT ["/usr/local/bin/vault-test"]
