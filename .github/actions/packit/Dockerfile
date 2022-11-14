FROM quay.io/packit/packit

RUN git config --system --add safe.directory /github/workspace

ENTRYPOINT ["./.github/test-packit.sh"]
