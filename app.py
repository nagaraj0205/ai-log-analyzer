import io
import json
import logging
import os
import re
import time
import zipfile
from collections import Counter

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)


# =========================
# CONFIGURATION
# =========================

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://ollama:11434/api/generate"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5-coder:3b"
)

OLLAMA_TEMPERATURE = float(
    os.getenv("OLLAMA_TEMPERATURE", "0.2")
)

OLLAMA_NUM_PREDICT = int(
    os.getenv("OLLAMA_NUM_PREDICT", "150")
)

OLLAMA_TIMEOUT = int(
    os.getenv("OLLAMA_TIMEOUT", "120")
)

MAX_LOG_LENGTH = int(
    os.getenv("MAX_LOG_LENGTH", "6000")
)

MAX_LOG_LINES = int(
    os.getenv("MAX_LOG_LINES", "80")
)

CONTEXT_LINES = int(
    os.getenv("CONTEXT_LINES", "2")
)

MAX_ERROR_GROUPS = int(
    os.getenv("MAX_ERROR_GROUPS", "25")
)


# =========================
# JENKINS CONFIGURATION
# =========================

JENKINS_URL = os.getenv(
    "JENKINS_URL",
    ""
).rstrip("/")

JENKINS_USER = os.getenv(
    "JENKINS_USER",
    ""
)

JENKINS_TOKEN = os.getenv(
    "JENKINS_TOKEN",
    ""
)


# =========================
# ARGO CD CONFIGURATION
# =========================

ARGOCD_URL = os.getenv(
    "ARGOCD_URL",
    ""
).rstrip("/")

ARGOCD_TOKEN = os.getenv(
    "ARGOCD_TOKEN",
    ""
)


# =========================
# GITHUB CONFIGURATION
# =========================

GITHUB_API = os.getenv(
    "GITHUB_API_URL",
    "https://api.github.com"
).rstrip("/")

GITHUB_TOKEN = os.getenv(
    "GITHUB_TOKEN",
    ""
)

# GITHUB_REPO is commonly set as a single "owner/repo" string
# (that's the format used in .env / .env.example). Support that,
# but still allow GITHUB_OWNER / GITHUB_REPO to be set separately
# if someone prefers that instead.
_github_owner_env = os.getenv("GITHUB_OWNER", "")
_github_repo_env = os.getenv("GITHUB_REPO", "")

if _github_owner_env:
    GITHUB_OWNER = _github_owner_env
    GITHUB_REPO = _github_repo_env
elif "/" in _github_repo_env:
    GITHUB_OWNER, GITHUB_REPO = _github_repo_env.split("/", 1)
else:
    GITHUB_OWNER = ""
    GITHUB_REPO = _github_repo_env


# =========================
# GENERAL HELPERS
# =========================

def mask_sensitive_data(text):
    if not text:
        return ""

    patterns = [
        (
            r"\bAKIA[0-9A-Z]{16}\b",
            "AKIA****************"
        ),
        (
            r"(?i)(aws_access_key_id\s*[=:]\s*)[^\s]+",
            r"\1********"
        ),
        (
            r"(?i)(aws_secret_access_key\s*[=:]\s*)[^\s]+",
            r"\1********"
        ),
        (
            r"(?i)(password\s*[=:]\s*)[^\s]+",
            r"\1********"
        ),
        (
            r"(?i)(passwd\s*[=:]\s*)[^\s]+",
            r"\1********"
        ),
        (
            r"(?i)(token\s*[=:]\s*)[^\s]+",
            r"\1********"
        ),
        (
            r"(?i)(access_token\s*[=:]\s*)[^\s]+",
            r"\1********"
        ),
        (
            r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+",
            r"\1********"
        ),
        (
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+",
            "Bearer ********"
        ),
        (
            r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
            "gh********"
        ),
        (
            r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?"
            r"-----END [A-Z ]+ PRIVATE KEY-----",
            "-----PRIVATE KEY REDACTED-----"
        ),
    ]

    result = text

    for pattern, replacement in patterns:
        result = re.sub(
            pattern,
            replacement,
            result,
            flags=re.MULTILINE | re.DOTALL
        )

    return result


def get_log_statistics(logs):
    lines = logs.splitlines()

    error_count = 0
    warning_count = 0
    info_count = 0

    for line in lines:
        lower = line.lower()

        if any(
            x in lower
            for x in [
                "error",
                "fatal",
                "exception",
                "failed",
                "failure",
                "crashloopbackoff",
                "imagepullbackoff",
                "oomkilled"
            ]
        ):
            error_count += 1

        elif any(
            x in lower
            for x in [
                "warn",
                "warning"
            ]
        ):
            warning_count += 1

        elif "info" in lower:
            info_count += 1

    return {
        "total_lines": len(lines),
        "error_lines": error_count,
        "warning_lines": warning_count,
        "info_lines": info_count,
        "total_characters": len(logs)
    }


def get_repeated_errors(logs):
    patterns = [
        "error",
        "exception",
        "failed",
        "failure",
        "fatal",
        "timeout",
        "oomkilled",
        "crashloopbackoff",
        "imagepullbackoff",
        "unhealthy",
        "connection refused",
        "permission denied",
        "access denied",
        "unauthorized",
        "forbidden",
        "500",
        "502",
        "503",
        "504"
    ]

    matches = []

    for line in logs.splitlines():
        line = line.strip()

        if not line:
            continue

        lower = line.lower()

        if any(
            pattern in lower
            for pattern in patterns
        ):
            normalized = re.sub(
                r"\b\d+\b",
                "<N>",
                line
            )

            normalized = re.sub(
                r"\s+",
                " ",
                normalized
            )

            matches.append(
                normalized[:300]
            )

    counter = Counter(matches)

    result = []

    for message, count in counter.most_common(
        MAX_ERROR_GROUPS
    ):
        result.append(
            {
                "message": message,
                "count": count
            }
        )

    return result


IMPORTANT_PATTERNS = [
    "error",
    "fatal",
    "exception",
    "failed",
    "failure",
    "warn",
    "warning",
    "timeout",
    "oomkilled",
    "crashloopbackoff",
    "imagepullbackoff",
    "unhealthy",
    "connection refused",
    "permission denied",
    "access denied",
    "unauthorized",
    "forbidden",
    "not found",
    "500",
    "501",
    "502",
    "503",
    "504"
]


def is_important_line(line):
    lower = line.lower()

    return any(
        pattern in lower
        for pattern in IMPORTANT_PATTERNS
    )


def reduce_logs(logs):
    if not logs:
        return ""

    lines = logs.splitlines()

    if (
        len(lines) <= MAX_LOG_LINES
        and len(logs) <= MAX_LOG_LENGTH
    ):
        return logs

    selected_indexes = set()

    for index, line in enumerate(lines):
        if is_important_line(line):
            start = max(
                0,
                index - CONTEXT_LINES
            )

            end = min(
                len(lines),
                index + CONTEXT_LINES + 1
            )

            for i in range(start, end):
                selected_indexes.add(i)

    if not selected_indexes:
        start = max(
            0,
            len(lines) - MAX_LOG_LINES
        )

        selected_indexes.update(
            range(start, len(lines))
        )

    selected = [
        lines[i]
        for i in sorted(selected_indexes)
    ]

    if len(selected) > MAX_LOG_LINES:
        important = [
            line
            for line in selected
            if is_important_line(line)
        ]

        normal = [
            line
            for line in selected
            if not is_important_line(line)
        ]

        remaining = max(
            0,
            MAX_LOG_LINES - len(important)
        )

        if remaining > 0:
            selected = important + normal[-remaining:]
        else:
            selected = important[:MAX_LOG_LINES]

    result = "\n".join(selected)

    if len(result) > MAX_LOG_LENGTH:
        result = result[:MAX_LOG_LENGTH]

    return result


def detect_source(logs):
    lower = logs.lower()

    if (
        "crashloopbackoff" in lower
        or "kubernetes" in lower
        or "kubectl" in lower
        or "pod/" in lower
    ):
        return "Kubernetes"

    if (
        "jenkins" in lower
        or "hudson" in lower
        or "jenkinsfile" in lower
    ):
        return "Jenkins"

    if (
        "argocd" in lower
        or "argo cd" in lower
    ):
        return "Argo CD"

    if (
        "github actions" in lower
        or "actions/checkout" in lower
    ):
        return "GitHub Actions"

    if (
        "ansible" in lower
        or "ansible-playbook" in lower
    ):
        return "Ansible"

    if (
        "docker" in lower
        or "container" in lower
    ):
        return "Docker"

    if (
        "systemd" in lower
        or "kernel:" in lower
        or "sshd" in lower
    ):
        return "Linux"

    return "Application"


# =========================
# OLLAMA AI ANALYSIS
# =========================

def analyze_with_ollama(logs, source=None):
    if not logs:
        return "No logs were provided for analysis."

    source = source or detect_source(logs)

    masked_logs = mask_sensitive_data(logs)

    reduced_logs = reduce_logs(masked_logs)

    statistics = get_log_statistics(masked_logs)

    repeated_errors = get_repeated_errors(
        masked_logs
    )

    if repeated_errors:
        repeated_error_text = "\n".join(
            [
                f"- {item['count']}x: {item['message']}"
                for item in repeated_errors
            ]
        )
    else:
        repeated_error_text = (
            "No repeated errors detected."
        )

    prompt = f"""
You are an experienced Cloud, DevOps and SRE engineer.

Analyze the following {source} logs.

Provide a concise production-oriented troubleshooting analysis.

Use exactly these sections:

1. Root Cause
2. Evidence from Logs
3. Impact
4. Recommended Fix
5. Verification Steps
6. Prevention

Rules:
- Do not invent information.
- Use evidence from the supplied logs.
- If the root cause cannot be confirmed, clearly say so.
- Give practical commands when useful.
- Focus on production troubleshooting.
- Keep the response concise.
- Keep the complete response under 300 words.
- Use plain text with a maximum of two relevant emojis.
- Do not invent errors, services, events or causes.
- Clearly separate evidence from assumptions.
- Do not expose or request passwords, tokens or secret values.
- Do not automatically execute any command.
- Do not recommend destructive commands.
- Never recommend chmod 666 or chmod 777.
- State where a command should run if you include one.
- For Docker logs, distinguish the host from the container.
- For Kubernetes logs, distinguish the pod, node and cluster.
- If the log shows success, do not invent a failure.
- Focus on the first meaningful error and its consequences.
- Do not present an unproven possible cause as the confirmed root cause.
- Do not recommend an action already shown in the log, such as retrying.
- Treat the calculated repeated-error list as authoritative.
- Never claim that a warning or error repeated unless it appears in that list.
- Describe the immediate failure separately from its underlying cause.
- If the underlying cause is not explicitly shown, state that it is unknown.
- Do not suggest latency, overload, resource exhaustion or network failure unless the log contains direct evidence.
- Do not recommend scaling, adding servers or changing timeouts without supporting evidence.

SOURCE:
{source}

LOG STATISTICS:
Total lines: {statistics["total_lines"]}
Error lines: {statistics["error_lines"]}
Warning lines: {statistics["warning_lines"]}
Total characters: {statistics["total_characters"]}

REPEATED ERRORS:
{repeated_error_text}

RELEVANT LOGS:
```text
{reduced_logs}
```
"""

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "10m",
        "options": {
            "temperature": OLLAMA_TEMPERATURE,
            "num_predict": OLLAMA_NUM_PREDICT
        }
    }

    start_time = time.time()

    logger.info(
        "Sending analysis to Ollama: source=%s original=%d reduced=%d",
        source,
        len(logs),
        len(reduced_logs)
    )

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT
        )

        elapsed = time.time() - start_time

        logger.info(
            "Ollama response received: status=%s time=%.2fs",
            response.status_code,
            elapsed
        )

        response.raise_for_status()

        data = response.json()

        result = data.get(
            "response",
            ""
        )

        if not result:
            return "Ollama returned an empty response."

        return result.strip()

    except requests.exceptions.Timeout:
        logger.exception(
            "Ollama request timed out"
        )

        return (
            "AI analysis timed out.\n\n"
            f"Model: {OLLAMA_MODEL}\n"
            f"Timeout: {OLLAMA_TIMEOUT} seconds\n\n"
            "Try reducing the log size or increasing "
            "OLLAMA_TIMEOUT."
        )

    except requests.exceptions.RequestException as exc:
        logger.exception(
            "Ollama request failed"
        )

        return (
            "AI analysis failed because Ollama "
            "could not be reached.\n\n"
            f"Error: {exc}"
        )

    except Exception as exc:
        logger.exception(
            "Unexpected Ollama error"
        )

        return (
            "AI analysis failed.\n\n"
            f"Error: {exc}"
        )


# =========================
# DOCKER
# =========================

def get_docker_client():
    import docker

    return docker.DockerClient(
        base_url="unix://var/run/docker.sock"
    )


@app.route(
    "/api/containers",
    methods=["GET"]
)
def get_containers():
    try:
        client = get_docker_client()

        containers = client.containers.list(
            all=True
        )

        result = []

        for container in containers:
            try:
                image = (
                    container.image.tags[0]
                    if container.image.tags
                    else str(container.image.id)
                )
            except Exception:
                image = "Unknown"

            result.append(
                {
                    "id": container.id,
                    "short_id": container.short_id,
                    "name": container.name,
                    "status": container.status,
                    "image": image
                }
            )

        return jsonify(result)

    except Exception as exc:
        logger.exception(
            "Docker containers request failed"
        )

        return jsonify(
            {
                "error": str(exc)
            }
        ), 500


@app.route(
    "/api/containers/<container_id>/logs",
    methods=["GET"]
)
def get_container_logs(container_id):
    try:
        client = get_docker_client()

        container = client.containers.get(
            container_id
        )

        logs = container.logs(
            stdout=True,
            stderr=True,
            tail=1000,
            timestamps=True
        )

        if isinstance(logs, bytes):
            logs = logs.decode(
                "utf-8",
                errors="replace"
            )

        return jsonify(
            {
                "logs": logs
            }
        )

    except Exception as exc:
        logger.exception(
            "Docker logs request failed"
        )

        return jsonify(
            {
                "error": str(exc),
                "logs": ""
            }
        ), 500


# =========================
# JENKINS
# =========================

def jenkins_request(
    path,
    params=None
):
    if not JENKINS_URL:
        raise RuntimeError(
            "JENKINS_URL is not configured."
        )

    url = (
        JENKINS_URL
        + "/"
        + path.lstrip("/")
    )

    auth = None

    if JENKINS_USER and JENKINS_TOKEN:
        auth = (
            JENKINS_USER,
            JENKINS_TOKEN
        )

    response = requests.get(
        url,
        auth=auth,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    return response


@app.route(
    "/api/jenkins/jobs",
    methods=["GET"]
)
def jenkins_jobs():
    try:
        response = jenkins_request(
            "/api/json",
            params={
                "tree": (
                    "jobs[name,url,color,"
                    "builds[number,result,"
                    "timestamp,duration,url]]"
                )
            }
        )

        data = response.json()

        return jsonify(
            {
                "jobs": data.get(
                    "jobs",
                    []
                )
            }
        )

    except Exception as exc:
        logger.exception(
            "Jenkins jobs request failed"
        )

        return jsonify(
            {
                "error": str(exc),
                "jobs": []
            }
        ), 500


@app.route(
    "/api/jenkins/jobs/<path:job_name>/builds/<int:build_number>/logs",
    methods=["GET"]
)
def jenkins_build_logs(
    job_name,
    build_number
):
    try:
        response = jenkins_request(
            f"/job/{job_name}/{build_number}/consoleText"
        )

        return jsonify(
            {
                "logs": response.text
            }
        )

    except Exception as exc:
        logger.exception(
            "Jenkins console log request failed"
        )

        return jsonify(
            {
                "error": str(exc),
                "logs": ""
            }
        ), 500


# =========================
# ARGO CD
# =========================

def argocd_headers():
    headers = {
        "Accept": "application/json"
    }

    if ARGOCD_TOKEN:
        headers["Authorization"] = (
            f"Bearer {ARGOCD_TOKEN}"
        )

    return headers


def argocd_request(
    path,
    params=None
):
    if not ARGOCD_URL:
        raise RuntimeError(
            "ARGOCD_URL is not configured."
        )

    url = (
        ARGOCD_URL
        + "/"
        + path.lstrip("/")
    )

    response = requests.get(
        url,
        headers=argocd_headers(),
        params=params,
        timeout=30,
        verify=False
    )

    response.raise_for_status()

    return response


@app.route(
    "/api/argocd/applications",
    methods=["GET"]
)
def argocd_applications():
    try:
        response = argocd_request(
            "/api/v1/applications"
        )

        data = response.json()

        return jsonify(data)

    except Exception as exc:
        logger.exception(
            "Argo CD applications request failed"
        )

        return jsonify(
            {
                "error": str(exc),
                "items": []
            }
        ), 500


@app.route(
    "/api/argocd/applications/<path:app_name>",
    methods=["GET"]
)
def argocd_application(
    app_name
):
    try:
        response = argocd_request(
            f"/api/v1/applications/{app_name}"
        )

        return jsonify(
            response.json()
        )

    except Exception as exc:
        logger.exception(
            "Argo CD application request failed"
        )

        return jsonify(
            {
                "error": str(exc)
            }
        ), 500


# =========================
# GITHUB ACTIONS
# =========================

def github_headers():
    headers = {
        "Accept": (
            "application/vnd.github+json"
        ),
        "X-GitHub-Api-Version": (
            "2022-11-28"
        )
    }

    if GITHUB_TOKEN:
        headers["Authorization"] = (
            f"Bearer {GITHUB_TOKEN}"
        )

    return headers


def github_request(
    path,
    params=None
):
    url = (
        GITHUB_API
        + "/"
        + path.lstrip("/")
    )

    response = requests.get(
        url,
        headers=github_headers(),
        params=params,
        timeout=30
    )

    response.raise_for_status()

    return response


def list_github_repos():
    """Return every repo GITHUB_OWNER has, across public and private,
    using the token if one is set so private repos are included too."""
    repos = []
    seen_full_names = set()

    if GITHUB_TOKEN:
        url = f"{GITHUB_API}/user/repos"
        params = {
            "per_page": 100,
            "affiliation": "owner,organization_member,collaborator",
            "sort": "full_name"
        }

        while url:
            response = requests.get(
                url,
                headers=github_headers(),
                params=params,
                timeout=30
            )
            response.raise_for_status()

            for repo in response.json():
                owner_login = (
                    (repo.get("owner") or {}).get("login", "")
                )

                if owner_login.lower() != GITHUB_OWNER.lower():
                    continue

                full_name = repo.get("full_name")

                if full_name in seen_full_names:
                    continue

                seen_full_names.add(full_name)

                repos.append(
                    {
                        "name": repo.get("name"),
                        "full_name": full_name,
                        "private": repo.get("private", False),
                        "updated_at": repo.get("updated_at")
                    }
                )

            url = response.links.get("next", {}).get("url")
            params = None

    if not repos:
        # No token, or the token can't see this owner's repos:
        # fall back to whatever is public.
        for endpoint in (
            f"/users/{GITHUB_OWNER}/repos",
            f"/orgs/{GITHUB_OWNER}/repos"
        ):
            try:
                response = github_request(
                    endpoint,
                    params={
                        "per_page": 100,
                        "sort": "full_name"
                    }
                )

                for repo in response.json():
                    repos.append(
                        {
                            "name": repo.get("name"),
                            "full_name": repo.get("full_name"),
                            "private": repo.get("private", False),
                            "updated_at": repo.get("updated_at")
                        }
                    )

                break

            except requests.exceptions.RequestException:
                continue

    repos.sort(key=lambda r: (r.get("name") or "").lower())

    return repos


@app.route(
    "/api/github/repos",
    methods=["GET"]
)
def github_repos():
    try:
        if not GITHUB_OWNER:
            raise RuntimeError(
                "GITHUB_OWNER is not configured."
            )

        repos = list_github_repos()

        return jsonify(
            {
                "repos": repos
            }
        )

    except Exception as exc:
        logger.exception(
            "GitHub repos request failed"
        )

        return jsonify(
            {
                "error": str(exc),
                "repos": []
            }
        ), 500


@app.route(
    "/api/github/runs",
    methods=["GET"]
)
def github_runs():
    try:
        if not GITHUB_OWNER:
            raise RuntimeError(
                "GITHUB_OWNER is not configured."
            )

        repo = request.args.get("repo") or GITHUB_REPO

        if not repo:
            raise RuntimeError(
                "No repository specified. Pass ?repo=<name> "
                "or set GITHUB_REPO as a default."
            )

        response = github_request(
            f"/repos/{GITHUB_OWNER}/{repo}/actions/runs",
            params={
                "per_page": 20
            }
        )

        data = response.json()

        return jsonify(data)

    except Exception as exc:
        logger.exception(
            "GitHub Actions runs request failed"
        )

        return jsonify(
            {
                "error": str(exc),
                "workflow_runs": []
            }
        ), 500


@app.route(
    "/api/github/runs/<int:run_id>/logs",
    methods=["GET"]
)
def github_run_logs(run_id):
    try:
        if not GITHUB_OWNER:
            raise RuntimeError(
                "GITHUB_OWNER is not configured."
            )

        repo = request.args.get("repo") or GITHUB_REPO

        if not repo:
            raise RuntimeError(
                "No repository specified. Pass ?repo=<name> "
                "or set GITHUB_REPO as a default."
            )

        url = (
            f"{GITHUB_API}/repos/"
            f"{GITHUB_OWNER}/"
            f"{repo}/"
            f"actions/runs/"
            f"{run_id}/logs"
        )

        response = requests.get(
            url,
            headers=github_headers(),
            timeout=30
        )

        response.raise_for_status()

        zip_data = io.BytesIO(
            response.content
        )

        logs = []

        with zipfile.ZipFile(
            zip_data
        ) as archive:

            for filename in archive.namelist():
                if filename.endswith("/"):
                    continue

                logs.append(
                    f"\n===== {filename} =====\n"
                )

                try:
                    content = archive.read(
                        filename
                    ).decode(
                        "utf-8",
                        errors="replace"
                    )

                    logs.append(content)

                except Exception as exc:
                    logs.append(
                        f"Unable to read log: {exc}"
                    )

        return jsonify(
            {
                "logs": "\n".join(logs)
            }
        )

    except Exception as exc:
        logger.exception(
            "GitHub Actions logs request failed"
        )

        return jsonify(
            {
                "error": str(exc),
                "logs": ""
            }
        ), 500


# =========================
# ANALYZER PAGE
# =========================

@app.route(
    "/analyze",
    methods=["GET"]
)
def analyzer_page():
    return render_template(
        "analyzer.html"
    )


# =========================
# AI ANALYZE API
# =========================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze_logs():
    try:
        data = request.get_json(
            silent=True
        ) or {}

        source = data.get(
            "source",
            "unknown"
        )

        logs = data.get(
            "logs",
            ""
        )

        if isinstance(
            logs,
            dict
        ):
            logs = json.dumps(
                logs,
                indent=2
            )

        elif not isinstance(
            logs,
            str
        ):
            logs = str(logs)

        if not logs.strip():
            return jsonify(
                {
                    "error": "No logs provided."
                }
            ), 400

        logger.info(
            "AI analysis requested: source=%s chars=%d",
            source,
            len(logs)
        )

        start_time = time.time()

        analysis = analyze_with_ollama(
            logs,
            source
        )

        elapsed = time.time() - start_time

        logger.info(
            "AI analysis completed in %.2fs",
            elapsed
        )

        return jsonify(
            {
                "analysis": analysis
            }
        )

    except Exception as exc:
        logger.exception(
            "AI analyze endpoint failed"
        )

        return jsonify(
            {
                "error": str(exc)
            }
        ), 500


# =========================
# HEALTH CHECK
# =========================

@app.route(
    "/health",
    methods=["GET"]
)
def health():
    return jsonify(
        {
            "status": "healthy",
            "service": "ai-log-analyzer",
            "ollama_url": OLLAMA_URL,
            "ollama_model": OLLAMA_MODEL,
            "docker": True,
            "jenkins": bool(JENKINS_URL),
            "argocd": bool(ARGOCD_URL),
            "github": bool(GITHUB_OWNER)
        }
    )


# =========================
# HOME PAGE
# =========================

@app.route(
    "/",
    methods=["GET"]
)
def index():
    return render_template(
        "index.html"
    )


# =========================
# START APPLICATION
# =========================

if __name__ == "__main__":
    logger.info(
        "========================================"
    )

    logger.info(
        "Starting AI Log Analyzer"
    )

    logger.info(
        "Ollama URL: %s",
        OLLAMA_URL
    )

    logger.info(
        "Ollama Model: %s",
        OLLAMA_MODEL
    )

    logger.info(
        "GitHub: %s/%s",
        GITHUB_OWNER or "NOT_CONFIGURED",
        GITHUB_REPO or "NOT_CONFIGURED"
    )

    logger.info(
        "Jenkins configured: %s",
        bool(JENKINS_URL)
    )

    logger.info(
        "Argo CD configured: %s",
        bool(ARGOCD_URL)
    )

    logger.info(
        "========================================"
    )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )