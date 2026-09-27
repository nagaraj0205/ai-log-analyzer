import os
import re
import io
import zipfile
import logging

import docker
import requests

from flask import Flask, jsonify, render_template, request


# ============================================================
# Flask
# ============================================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)


# ============================================================
# Environment Variables
# ============================================================

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://ollama:11434/api/generate"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5-coder:3b"
)

MAX_LOG_LENGTH = int(
    os.getenv("MAX_LOG_LENGTH", "12000")
)


# Jenkins

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


# Argo CD

ARGOCD_URL = os.getenv(
    "ARGOCD_URL",
    ""
).rstrip("/")

ARGOCD_TOKEN = os.getenv(
    "ARGOCD_TOKEN",
    "" 
)


# GitHub

GITHUB_TOKEN = os.getenv(
    "GITHUB_TOKEN",
    ""
)

GITHUB_REPO = os.getenv(
    "GITHUB_REPO",
    ""
)

GITHUB_API_URL = os.getenv(
    "GITHUB_API_URL",
    "https://api.github.com"
).rstrip("/")


# ============================================================
# Docker Client
# ============================================================

try:

    docker_client = docker.from_env()

    docker_client.ping()

    logger.info(
        "Docker client connected successfully"
    )

except Exception as e:

    docker_client = None

    logger.warning(
        "Docker client unavailable: %s",
        e
    )


# ============================================================
# Supported Log Types
# ============================================================

SUPPORTED_LOG_TYPES = [
    "auto",
    "docker",
    "kubernetes",
    "jenkins",
    "linux",
    "application",
    "ansible",
    "argocd",
    "github-actions"
]


# ============================================================
# Sensitive Data Masking
# ============================================================

def mask_sensitive_data(text):

    if not text:
        return text

    patterns = [

        (
            r'(?i)(password\s*[=:]\s*)[^\s]+',
            r'\1[MASKED]'
        ),

        (
            r'(?i)(passwd\s*[=:]\s*)[^\s]+',
            r'\1[MASKED]'
        ),

        (
            r'(?i)(token\s*[=:]\s*)[^\s]+',
            r'\1[MASKED]'
        ),

        (
            r'(?i)(api[_-]?key\s*[=:]\s*)[^\s]+',
            r'\1[MASKED]'
        ),

        (
            r'(?i)(secret\s*[=:]\s*)[^\s]+',
            r'\1[MASKED]'
        ),

        (
            r'(?i)(authorization:\s*bearer\s+)[^\s]+',
            r'\1[MASKED]'
        ),

        (
            r'(?i)(aws_access_key_id\s*[=:]\s*)[A-Z0-9]+',
            r'\1[MASKED]'
        ),

        (
            r'(?i)(aws_secret_access_key\s*[=:]\s*)[^\s]+',
            r'\1[MASKED]'
        )
    ]

    for pattern, replacement in patterns:

        text = re.sub(
            pattern,
            replacement,
            text
        )

    return text


# ============================================================
# Automatic Log Source Detection
# ============================================================

def detect_log_source(logs):

    if not logs:
        return "unknown"

    text = logs.lower()

    if (
        "play [" in text
        or "task [" in text
        or "play recap" in text
        or "ansible-playbook" in text
        or "unreachable!" in text
        or "fatal: [" in text
    ):
        return "ansible"

    if (
        "github actions" in text
        or "runner version:" in text
        or "##[error]" in text
        or "##[command]" in text
    ):
        return "github-actions"

    if (
        "argocd" in text
        or "argocd-server" in text
        or "sync status" in text
    ):
        return "argocd"

    if (
        "jenkins" in text
        or "[pipeline]" in text
        or "hudson." in text
        or "started by user" in text
    ):
        return "jenkins"

    if (
        "crashloopbackoff" in text
        or "kubectl" in text
        or "pod/" in text
        or "containercreating" in text
        or "imagepullbackoff" in text
    ):
        return "kubernetes"

    if (
        "docker" in text
        or "containerd" in text
        or "docker daemon" in text
    ):
        return "docker"

    if (
        "systemd" in text
        or "kernel:" in text
        or "journalctl" in text
    ):
        return "linux"

    return "application"


# ============================================================
# Statistics
# ============================================================

def get_statistics(logs):

    lines = logs.splitlines()

    error_count = len(
        re.findall(
            r"(?i)\b(error|err|failed|failure|fatal)\b",
            logs
        )
    )

    warning_count = len(
        re.findall(
            r"(?i)\b(warn|warning)\b",
            logs
        )
    )

    critical_count = len(
        re.findall(
            r"(?i)\b(critical|panic|oom|out of memory)\b",
            logs
        )
    )

    return {
        "lines": len(lines),
        "characters": len(logs),
        "errors": error_count,
        "warnings": warning_count,
        "critical": critical_count
    }


# ============================================================
# Repeated Errors
# ============================================================

def find_repeated_errors(logs):

    counter = {}

    for line in logs.splitlines():

        if re.search(
            r"(?i)(error|failed|failure|fatal|exception)",
            line
        ):

            cleaned = line.strip()

            if cleaned:

                counter[cleaned] = (
                    counter.get(cleaned, 0) + 1
                )

    repeated = sorted(
        counter.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return repeated[:10]


# ============================================================
# Safety Check
# ============================================================

def safety_check(logs):

    blocked_patterns = [
        r"(?i)rm\s+-rf\s+/",
        r"(?i)mkfs\.",
        r"(?i)dd\s+if=.*of=/dev/",
        r"(?i)curl.*\|\s*bash",
        r"(?i)wget.*\|\s*bash"
    ]

    for pattern in blocked_patterns:

        if re.search(pattern, logs):

            return False

    return True


# ============================================================
# Headers
# ============================================================

def make_headers():

    return {
        "Accept": "application/json"
    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# ANALYZER PAGE
# ============================================================

@app.route("/analyze")
def analyzer():

    return render_template(
        "analyzer.html"
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "ollama_url": OLLAMA_URL,
        "model": OLLAMA_MODEL,
        "docker_connected": docker_client is not None
    })


# ============================================================
# DOCKER
# ============================================================

@app.route("/api/containers")
def containers():

    if docker_client is None:

        return jsonify({
            "error": "Docker is not available"
        }), 503

    try:

        items = []

        for container in docker_client.containers.list(
            all=True
        ):

            image = ""

            try:
                image = container.image.tags[0]
            except Exception:
                image = container.image.short_id

            items.append({

                "id": container.id,

                "name": container.name,

                "image": image,

                "status": container.status
            })

        return jsonify(items)

    except Exception as e:

        logger.exception(
            "Unable to list Docker containers"
        )

        return jsonify({
            "error": str(e)
        }), 500


@app.route(
    "/api/containers/<container_id>/logs"
)
def container_logs(container_id):

    if docker_client is None:

        return jsonify({
            "error": "Docker is not available"
        }), 503

    try:

        container = docker_client.containers.get(
            container_id
        )

        logs = container.logs(
            stdout=True,
            stderr=True,
            tail=5000
        ).decode(
            "utf-8",
            errors="replace"
        )

        logs = mask_sensitive_data(logs)

        logs = logs[-MAX_LOG_LENGTH:]

        return jsonify({

            "source": "docker",

            "container": container.name,

            "logs": logs

        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# JENKINS
# ============================================================

def jenkins_auth():

    if not JENKINS_USER or not JENKINS_TOKEN:

        return None

    return (
        JENKINS_USER,
        JENKINS_TOKEN
    )


@app.route("/api/jenkins/status")
def jenkins_status():

    if not JENKINS_URL:

        return jsonify({
            "configured": False
        })

    try:

        response = requests.get(
            f"{JENKINS_URL}/api/json",
            auth=jenkins_auth(),
            timeout=10
        )

        response.raise_for_status()

        return jsonify({
            "configured": True,
            "online": True
        })

    except Exception as e:

        return jsonify({
            "configured": True,
            "online": False,
            "error": str(e)
        })


@app.route("/api/jenkins/jobs")
def jenkins_jobs():

    if not JENKINS_URL:

        return jsonify({
            "error": "Jenkins is not configured"
        }), 503

    try:

        response = requests.get(
            f"{JENKINS_URL}/api/json",
            params={
                "tree": (
                    "jobs[name,url,color,"
                    "lastBuild[number,result,"
                    "timestamp,duration]]"
                )
            },
            auth=jenkins_auth(),
            timeout=15
        )

        response.raise_for_status()

        return jsonify(
            response.json()
        )

    except Exception as e:

        logger.exception(
            "Unable to retrieve Jenkins jobs"
        )

        return jsonify({
            "error": str(e)
        }), 500


@app.route(
    "/api/jenkins/jobs/<path:job_name>/builds"
)
def jenkins_builds(job_name):

    if not JENKINS_URL:

        return jsonify({
            "error": "Jenkins is not configured"
        }), 503

    try:

        url = (
            f"{JENKINS_URL}/job/"
            f"{job_name}/api/json"
        )

        response = requests.get(
            url,
            params={
                "tree": (
                    "builds[number,result,"
                    "timestamp,duration,url]"
                )
            },
            auth=jenkins_auth(),
            timeout=15
        )

        response.raise_for_status()

        return jsonify(
            response.json()
        )

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


@app.route(
    "/api/jenkins/jobs/<path:job_name>/"
    "builds/<int:build_number>/logs"
)
def jenkins_build_logs(
    job_name,
    build_number
):

    if not JENKINS_URL:

        return jsonify({
            "error": "Jenkins is not configured"
        }), 503

    try:

        url = (
            f"{JENKINS_URL}/job/"
            f"{job_name}/{build_number}/consoleText"
        )

        response = requests.get(
            url,
            auth=jenkins_auth(),
            timeout=30
        )

        response.raise_for_status()

        logs = response.text

        logs = mask_sensitive_data(logs)

        logs = logs[-MAX_LOG_LENGTH:]

        return jsonify({

            "source": "jenkins",

            "job": job_name,

            "build": build_number,

            "logs": logs

        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# ARGO CD
# ============================================================

def argocd_headers():

    return {
        "Authorization": f"Bearer {ARGOCD_TOKEN}",
        "Accept": "application/json"
    }


@app.route("/api/argocd/status")
def argocd_status():

    if not ARGOCD_URL:

        return jsonify({
            "configured": False
        })

    try:

        response = requests.get(
            f"{ARGOCD_URL}/api/version",
            headers=argocd_headers(),
            timeout=10,
            verify=False
        )

        return jsonify({

            "configured": True,

            "online": response.ok,

            "status_code": response.status_code

        })

    except Exception as e:

        return jsonify({

            "configured": True,

            "online": False,

            "error": str(e)

        })


@app.route("/api/argocd/applications")
def argocd_applications():

    if not ARGOCD_URL:

        return jsonify({
            "error": "Argo CD is not configured"
        }), 503

    try:

        response = requests.get(

            f"{ARGOCD_URL}/api/v1/applications",

            headers=argocd_headers(),

            timeout=20,

            verify=False

        )

        response.raise_for_status()

        return jsonify(
            response.json()
        )

    except Exception as e:

        logger.exception(
            "Unable to retrieve Argo CD applications"
        )

        return jsonify({
            "error": str(e)
        }), 500


@app.route(
    "/api/argocd/applications/<path:name>"
)
def argocd_application(name):

    if not ARGOCD_URL:

        return jsonify({
            "error": "Argo CD is not configured"
        }), 503

    try:

        response = requests.get(

            f"{ARGOCD_URL}/api/v1/applications/{name}",

            headers=argocd_headers(),

            timeout=20,

            verify=False

        )

        response.raise_for_status()

        return jsonify(
            response.json()
        )

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# GITHUB
# ============================================================

def github_headers():

    return {

        "Authorization":
            f"Bearer {GITHUB_TOKEN}",

        "Accept":
            "application/vnd.github+json",

        "X-GitHub-Api-Version":
            "2022-11-28"
    }


@app.route("/api/github/status")
def github_status():

    if not GITHUB_TOKEN or not GITHUB_REPO:

        return jsonify({

            "configured": False

        })

    try:

        response = requests.get(

            f"{GITHUB_API_URL}/repos/"
            f"{GITHUB_REPO}",

            headers=github_headers(),

            timeout=15

        )

        return jsonify({

            "configured": True,

            "online": response.ok,

            "status_code":
                response.status_code

        })

    except Exception as e:

        return jsonify({

            "configured": True,

            "online": False,

            "error": str(e)

        })


@app.route("/api/github/runs")
def github_runs():

    if not GITHUB_TOKEN or not GITHUB_REPO:

        return jsonify({

            "error":
                "GitHub is not configured"

        }), 503

    try:

        url = (

            f"{GITHUB_API_URL}/repos/"
            f"{GITHUB_REPO}/actions/runs"

        )

        response = requests.get(

            url,

            headers=github_headers(),

            params={
                "per_page": 20
            },

            timeout=20

        )

        response.raise_for_status()

        return jsonify(
            response.json()
        )

    except Exception as e:

        logger.exception(
            "Unable to retrieve GitHub workflow runs"
        )

        return jsonify({

            "error": str(e)

        }), 500


# ============================================================
# GITHUB ACTIONS LOGS
# ============================================================

@app.route(
    "/api/github/runs/<int:run_id>/logs"
)
def github_run_logs(run_id):

    if not GITHUB_TOKEN or not GITHUB_REPO:

        return jsonify({

            "error":
                "GitHub is not configured"

        }), 503

    try:

        url = (

            f"{GITHUB_API_URL}/repos/"
            f"{GITHUB_REPO}/actions/runs/"
            f"{run_id}/logs"

        )

        logger.info(
            "Downloading GitHub Actions logs "
            "for run %s",
            run_id
        )

        response = requests.get(

            url,

            headers=github_headers(),

            timeout=60

        )

        response.raise_for_status()

        zip_data = io.BytesIO(
            response.content
        )

        extracted_logs = []

        with zipfile.ZipFile(
            zip_data,
            "r"
        ) as archive:

            for filename in archive.namelist():

                if filename.endswith("/"):
                    continue

                try:

                    content = archive.read(
                        filename
                    ).decode(
                        "utf-8",
                        errors="replace"
                    )

                    extracted_logs.append(

                        "\n"
                        + "=" * 80
                        + "\n"
                        + f"FILE: {filename}\n"
                        + "=" * 80
                        + "\n"
                        + content

                    )

                except Exception as file_error:

                    logger.warning(

                        "Could not read "
                        "GitHub log %s: %s",

                        filename,

                        file_error

                    )

        logs = "\n".join(
            extracted_logs
        )

        logs = mask_sensitive_data(
            logs
        )

        logs = logs[-MAX_LOG_LENGTH:]

        if not logs.strip():

            return jsonify({

                "error":
                    "GitHub returned an empty "
                    "workflow log archive."

            }), 404

        return jsonify({

            "source":
                "github-actions",

            "run_id":
                run_id,

            "logs":
                logs

        })

    except zipfile.BadZipFile:

        return jsonify({

            "error":
                "GitHub returned logs, "
                "but the response was not "
                "a valid ZIP archive."

        }), 500

    except requests.HTTPError as e:

        status_code = (

            e.response.status_code

            if e.response is not None

            else 500

        )

        if status_code == 404:

            return jsonify({

                "error":
                    "Workflow logs are not available. "
                    "The run may still be running, "
                    "or the logs may have expired."

            }), 404

        return jsonify({

            "error": str(e)

        }), status_code

    except Exception as e:

        logger.exception(

            "Unable to retrieve GitHub Actions logs"

        )

        return jsonify({

            "error": str(e)

        }), 500


# ============================================================
# GENERIC AI ANALYSIS
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def analyze():

    data = request.get_json(
        silent=True
    ) or {}

    logs = data.get(
        "logs",
        ""
    )

    source = data.get(
        "source",
        "auto"
    )

    if not logs.strip():

        return jsonify({

            "error":
                "No logs provided"

        }), 400

    if source not in SUPPORTED_LOG_TYPES:

        source = "auto"

    logs = logs[:MAX_LOG_LENGTH]

    logs = mask_sensitive_data(
        logs
    )

    if not safety_check(logs):

        return jsonify({

            "error":
                "Potentially destructive "
                "command detected in logs. "
                "Analysis blocked."

        }), 400

    detected_source = detect_log_source(
        logs
    )

    if source == "auto":

        source = detected_source

    statistics = get_statistics(
        logs
    )

    repeated_errors = find_repeated_errors(
        logs
    )

    repeated_text = "\n".join(

        f"- {line} "
        f"(count: {count})"

        for line, count in repeated_errors

    )

    prompt = f"""
You are an experienced Cloud and DevOps
production troubleshooting assistant.

Analyze ONLY the supplied logs.

Do not invent information.

Do not assume infrastructure that is not
visible in the logs.

LOG SOURCE:
{source}

DETECTED SOURCE:
{detected_source}

LOG STATISTICS:
{statistics}

REPEATED ERRORS:
{repeated_text}

LOGS:
--------------------
{logs}
--------------------

Provide the analysis using exactly these sections:

1. Summary
2. Severity
3. Evidence
4. Root Cause
5. Impact
6. Troubleshooting Steps
7. Recommended Fix
8. Prevention
9. Useful Commands

Rules:

- Every important conclusion must be supported
  by evidence in the logs.
- If the root cause cannot be confirmed,
  clearly say that it cannot be confirmed.
- Separate confirmed evidence from likely causes.
- Do not invent pod names, EC2 IDs, IP addresses,
  error codes, database names, or infrastructure.
- Commands must be relevant to the observed issue.
- Do not recommend destructive commands unless
  clearly required and explain their impact.
"""

    try:

        response = requests.post(

            OLLAMA_URL,

            json={

                "model":
                    OLLAMA_MODEL,

                "prompt":
                    prompt,

                "stream":
                    False

            },

            timeout=180

        )

        response.raise_for_status()

        result = response.json()

        analysis = result.get(
            "response",
            ""
        )

        if not analysis:

            analysis = (
                "Ollama returned an empty response."
            )

        return jsonify({

            "source":
                source,

            "detected_source":
                detected_source,

            "statistics":
                statistics,

            "analysis":
                analysis

        })

    except requests.RequestException as e:

        logger.exception(
            "Ollama request failed"
        )

        return jsonify({

            "error":
                f"Ollama request failed: {e}"

        }), 502

    except Exception as e:

        logger.exception(
            "Analysis failed"
        )

        return jsonify({

            "error":
                str(e)

        }), 500


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=int(
            os.getenv(
                "PORT",
                "5000"
            )
        ),

        debug=False

    )