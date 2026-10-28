# T5 verifier image — WHEELS-BUNDLED edition (offline pip).
#
# Why this variant exists: on some networks the container can reach
# pypi.org but TLS to files.pythonhosted.org (where the actual wheel
# files live) consistently fails with SSLV3_ALERT_HANDSHAKE_FAILURE
# (observed 2026-10-27, twice, same URL). The pip installs below are
# therefore fully offline: every wheel (tools + dependencies) is baked
# into the image from wheels/, and the build never contacts PyPI.
# Every bundled wheel was verified byte-for-byte against the SHA-256
# PyPI publishes for that exact file before packaging.
#
# Still needed at build time: Docker Hub (base image pull).
# Still needed at run time: github.com (corpus/rule checkouts, cloned
# on first container run).
#
# Deliberately NO proxy build args here: nothing in this build needs
# a proxy, and a placeholder/bogus proxy value breaks apt (seen
# 2026-10-27). Build with a plain `docker build -t t5-verify .`
FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY wheels/ /wheels/

# Two tool environments, mirroring the original run exactly:
# old = Semgrep 1.172.0 + Flawfinder 2.0.19; new = Semgrep 1.182.0 + Flawfinder 2.0.20.
# --no-index: never touch PyPI; resolve everything from /wheels.
RUN python3 -m venv /opt/venvs/venv-old \
    && /opt/venvs/venv-old/bin/pip install --no-index --find-links /wheels "semgrep==1.172.0" "flawfinder==2.0.19" \
    && python3 -m venv /opt/venvs/venv-new \
    && /opt/venvs/venv-new/bin/pip install --no-index --find-links /wheels "semgrep==1.182.0" "flawfinder==2.0.20"

COPY scripts/ /app/scripts/
COPY manifests/ /app/manifests/
COPY bundle/ /bundle/

WORKDIR /work
ENTRYPOINT ["python3", "/app/scripts/driver.py"]
