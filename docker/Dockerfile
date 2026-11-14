# Optional "hard isolation" profile.
#
# The policy layer is a reference monitor inside the agent's process; it cannot
# stop a native-code escape. This image is what does: no network namespace, a
# read-only root filesystem, and a tmpfs for the eval workspaces.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY policy.example.yaml ./
COPY benchmarks ./benchmarks

RUN pip install --no-cache-dir . && useradd -m -u 10001 agent

USER agent

ENTRYPOINT ["python", "benchmarks/run_evals.py"]
CMD ["--scripted"]
