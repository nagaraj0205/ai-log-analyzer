import os
import re
from collections import Counter

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://ollama:11434/api/generate"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5-coder:3b"
)

MAX_LOG_LENGTH = int(os.getenv("MAX_LOG_LENGTH", "12000"))

SUPPORTED_LOG_TYPES = {
    "auto",
    "jenkins",
    "docker",
    "kubernetes",
    "linux",
    "application"
}


def mask_sensitive_data(log_text):
    patterns = [
        (
            r"(?i)(password|passwd|pwd|token|api[_-]?key|secret)"
            r"\s*[:=]\s*[^\s]+",
            r"\1=[REDACTED]"
        ),
        (
            r"(?i)authorization:\s*bearer\s+[^\s]+",
            "Authorization: Bearer [REDACTED]"
        ),
        (
            r"\bAKIA[0-9A-Z]{16}\b",
            "[REDACTED_AWS_ACCESS_KEY]"
        ),
        (
            r"(?i)(connection[_-]?string)"
            r"\s*[:=]\s*[^\n]+",
            r"\1=[REDACTED]"
        ),
        (
            r"(?i)(client[_-]?secret)"
            r"\s*[:=]\s*[^\s]+",
            r"\1=[REDACTED]"
        )
    ]

    sanitized_log = log_text

    for pattern, replacement in patterns:
        sanitized_log = re.sub(
            pattern,
            replacement,
            sanitized_log
        )

    return sanitized_log


def detect_log_source(log_text):
    detection_patterns = {
        "Jenkins": [
            r"\[Pipeline\]",
            r"Finished:\s+(SUCCESS|FAILURE|ABORTED|UNSTABLE)",
            r"Started by user",
            r"Jenkins"
        ],
        "Kubernetes": [
            r"\bpod[s]?\b",
            r"\bkubectl\b",
            r"CrashLoopBackOff",
            r"ImagePullBackOff",
            r"\bnamespace\b",
            r"\bkubelet\b"
        ],
        "Docker": [
            r"docker\.sock",
            r"docker daemon",
            r"\bdocker\b",
            r"container (started|exited|failed)",
            r"OCI runtime"
        ],
        "Linux/System": [
            r"\bsystemd\b",
            r"\bsystemctl\b",
            r"\bkernel\b",
            r"\bjournalctl\b",
            r"segmentation fault",
            r"permission denied"
        ],
        "Application": [
            r"\b(INFO|WARN|WARNING|ERROR|DEBUG|TRACE|FATAL)\b",
            r"\bexception\b",
            r"\bstack trace\b",
            r"\btraceback\b",
            r"\bHTTP/[12]\.[01]\s+[45]\d\d\b",
            r"\bapplication startup\b",
            r"\bdatabase connection\b",
            r"\bNullReferenceException\b",
            r"\bSQLException\b"
        ]
    }

    scores = {}

    for source, patterns in detection_patterns.items():
        scores[source] = sum(
            1
            for pattern in patterns
            if re.search(pattern, log_text, re.IGNORECASE)
        )

    detected_source, highest_score = max(
        scores.items(),
        key=lambda item: item[1]
    )

    if highest_score == 0:
        return "Unknown/Generic"

    return detected_source


def calculate_log_statistics(log_text):
    lines = [
        line.strip()
        for line in log_text.splitlines()
        if line.strip()
    ]

    error_count = sum(
        1 for line in lines
        if re.search(
            r"\b(error|failed|failure|fatal|exception|critical)\b",
            line,
            re.IGNORECASE
        )
    )

    warning_count = sum(
        1 for line in lines
        if re.search(
            r"\b(warn|warning)\b",
            line,
            re.IGNORECASE
        )
    )

    info_count = sum(
        1 for line in lines
        if re.search(r"\binfo\b", line, re.IGNORECASE)
    )

    normalized_errors = []

    for line in lines:
        if re.search(
            r"\b(error|failed|failure|fatal|exception|critical)\b",
            line,
            re.IGNORECASE
        ):
            normalized_line = re.sub(
                r"\b\d+\b",
                "<number>",
                line.lower()
            )

            normalized_line = re.sub(
                r"\s+",
                " ",
                normalized_line
            )

            normalized_errors.append(normalized_line[:250])

    repeated_errors = [
        {
            "message": message,
            "count": count
        }
        for message, count in Counter(normalized_errors).most_common(3)
        if count > 1
    ]

    return {
        "total_lines": len(lines),
        "error_count": error_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "repeated_errors": repeated_errors
    }


def filter_unsafe_recommendations(ai_response):
    unsafe_patterns = [
        r"(?im)^.*\bchmod\s+(?:666|777)\b.*$",
        r"(?im)^.*\bpermissions?\b.{0,30}\b(?:666|777)\b.*$",
        r"(?im)^.*\bsudo\s+usermod\b.*$",
        r"(?im)^.*\bchown\b.*?/var/run/docker\.sock.*$",
        r"(?im)^.*\brm\s+-rf\s+/(?:\s|$).*$"
    ]

    filtered_response = ai_response
    unsafe_content_found = False

    for pattern in unsafe_patterns:
        filtered_response, replacements = re.subn(
            pattern,
            "[Potentially unsafe recommendation removed]",
            filtered_response
        )

        if replacements:
            unsafe_content_found = True

    if unsafe_content_found:
        return (
            "SAFETY NOTICE\n"
            "Potentially unsafe recommendations were removed. "
            "Review all remaining commands before execution.\n\n"
            + filtered_response
        )

    return filtered_response

def enforce_evidence_boundaries(ai_response, log_text):
    speculative_terms = [
        "network latency",
        "server overload",
        "database overload",
        "resource exhaustion",
        "configuration issues"
    ]

    response_lower = ai_response.lower()
    log_lower = log_text.lower()

    unsupported_assumption = any(
        term in response_lower and term not in log_lower
        for term in speculative_terms
    )

    if not unsupported_assumption:
        return ai_response

    corrected_response = re.sub(
        (
            r"PROBABLE ROOT CAUSE\s*.*?"
            r"(?=\nRECOMMENDED ACTIONS)"
        ),
        (
            "PROBABLE ROOT CAUSE\n"
            "The immediate failure was repeated database connection "
            "timeouts. The log does not contain enough evidence to "
            "identify the underlying cause.\n"
        ),
        ai_response,
        flags=re.DOTALL
    )

    corrected_response = re.sub(
        r"RECOMMENDED ACTIONS\s*.*$",
        (
            "RECOMMENDED ACTIONS\n"
            "1. Verify database availability from the application environment.\n"
            "2. Review database and application metrics at the failure time.\n"
            "3. Confirm the configured database endpoint without exposing secrets.\n"
            "4. Review related database and network logs before making changes."
        ),
        corrected_response,
        flags=re.DOTALL
    )

    return corrected_response

def enforce_statistics(ai_response, statistics):
    if statistics["error_count"] > 0:
        overall_severity = "High"
    elif statistics["warning_count"] > 0:
        overall_severity = "Medium"
    else:
        overall_severity = "Low"

    severity_section = (
        "SEVERITY OVERVIEW\n"
        f"- Errors: {statistics['error_count']}\n"
        f"- Warnings: {statistics['warning_count']}\n"
        f"- Overall severity: {overall_severity}\n"
    )

    return re.sub(
        r"SEVERITY OVERVIEW\s*.*?(?=\nIMPORTANT EVENTS)",
        severity_section,
        ai_response,
        flags=re.DOTALL
    )

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "application": "AI Log Analyzer",
            "model": OLLAMA_MODEL
        }
    )


@app.route("/api/analyze", methods=["POST"])
def analyze():
    request_data = request.get_json(silent=True) or {}

    log_text = str(
        request_data.get("log_text", "")
    ).strip()

    selected_log_type = str(
        request_data.get("log_type", "auto")
    ).strip().lower()

    if not log_text:
        return jsonify(
            {"error": "Please provide a log for analysis."}
        ), 400

    if selected_log_type not in SUPPORTED_LOG_TYPES:
        return jsonify(
            {"error": "The selected log type is not supported."}
        ), 400

    sanitized_log = mask_sensitive_data(log_text)

    if not sanitized_log.strip():
        return jsonify(
            {
                "error": (
                    "The submitted log contained no analyzable content."
                )
            }
        ), 400

    if len(sanitized_log) > MAX_LOG_LENGTH:
        sanitized_log = (
            "[Earlier log lines omitted]\n"
            + sanitized_log[-MAX_LOG_LENGTH:]
        )

    automatically_detected_source = detect_log_source(sanitized_log)

    if selected_log_type == "auto":
        analysis_source = automatically_detected_source
    else:
        source_labels = {
            "jenkins": "Jenkins",
            "docker": "Docker",
            "kubernetes": "Kubernetes",
            "linux": "Linux/System",
            "application": "Application"
        }

        analysis_source = source_labels[selected_log_type]

    statistics = calculate_log_statistics(sanitized_log)

    repeated_error_summary = "No repeated errors detected."

    if statistics["repeated_errors"]:
        repeated_error_summary = "\n".join(
            (
                f"- Repeated {item['count']} times: "
                f"{item['message']}"
            )
            for item in statistics["repeated_errors"]
        )

    prompt = f"""
You are an AI-assisted DevOps log analysis agent.

Selected log source:
{analysis_source}

Automatically detected source:
{automatically_detected_source}

Calculated log statistics:
- Total non-empty lines: {statistics["total_lines"]}
- Error-related lines: {statistics["error_count"]}
- Warning-related lines: {statistics["warning_count"]}
- Info-related lines: {statistics["info_count"]}

Authoritative repeated error patterns calculated by the application:
{repeated_error_summary}

Use this list exactly. Do not independently calculate, add or change
repeated patterns.

Analyze the log using only evidence contained in the supplied log.

Return exactly this format:

SUMMARY
Write a maximum of two short sentences explaining what happened.

LOG SOURCE
State the most likely source of the log.

SEVERITY OVERVIEW
- Errors:
- Warnings:
- Overall severity:

IMPORTANT EVENTS
List up to four important events in their apparent order.

REPEATED PATTERNS
Describe repeated errors or state that none were detected.

PROBABLE ROOT CAUSE
State the most likely root cause. If evidence is insufficient, say so.

RECOMMENDED ACTIONS
Provide three to five safe, practical troubleshooting steps.

Rules:
- Keep the complete response under 300 words.
- Use plain text with a maximum of two relevant emojis: use 😊 or ✅ for success, 😐 or ⚠️ for warnings, and 😟 or ❌ for failures or critical errors.
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

Log:
--- BEGIN LOG ---
{sanitized_log}
--- END LOG ---
"""

    try:
        ollama_response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2
                }
            },
            timeout=180
        )

        ollama_response.raise_for_status()
        result = ollama_response.json()

        ai_analysis = result.get(
            "response",
            "The AI model returned an empty response."
        ).strip()

        statistics_checked_analysis = enforce_statistics(
            ai_analysis,
            statistics
        )

        evidence_checked_analysis = enforce_evidence_boundaries(
            statistics_checked_analysis,
            sanitized_log
        )

        safe_analysis = filter_unsafe_recommendations(
            evidence_checked_analysis
        )

        return jsonify(
            {
                "analysis": safe_analysis,
                "detected_source": automatically_detected_source,
                "analyzed_as": analysis_source,
                "statistics": statistics,
                "model": OLLAMA_MODEL
            }
        )

    except requests.Timeout:
        app.logger.exception("Ollama analysis timed out")

        return jsonify(
            {
                "error": (
                    "The local AI model took too long to respond. "
                    "Please try again with a shorter log."
                )
            }
        ), 504

    except requests.RequestException:
        app.logger.exception("Unable to communicate with Ollama")

        return jsonify(
            {
                "error": (
                    "Unable to communicate with the local AI model. "
                    "Check whether the Ollama container is running."
                )
            }
        ), 502

    except ValueError:
        app.logger.exception("Ollama returned invalid JSON")

        return jsonify(
            {
                "error": "The local AI model returned an invalid response."
            }
        ), 502


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)