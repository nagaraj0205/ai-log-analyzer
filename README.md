# AI-Powered Log Analyzer for DevOps Troubleshooting

An AI-powered log analysis application that helps identify potential issues, summarize log evidence, and suggest troubleshooting steps across DevOps environments.

Built with Python, Flask, Docker, and Ollama, the application processes logs, masks sensitive information, and reduces unnecessary content before sending relevant evidence to an AI model.

> AI supports troubleshooting—it does not replace investigation. Findings should be verified against logs, metrics, events, configuration, network connectivity, and IAM permissions.

## Project Overview

Production logs can be large, repetitive, and difficult to investigate manually. This project adds an AI-assisted analysis layer to help organize relevant evidence and recommend next steps.

### Key Features

- Log analysis for multiple DevOps sources.
- Sensitive data masking before AI processing.
- Log reduction with surrounding context preservation.
- Repeated error pattern identification.
- Structured AI-generated troubleshooting reports.
- Configurable inference settings to manage response time and resource usage.
- Health endpoint for application verification.

### Technology Stack

| Component | Technology |
|-----------|------------|
| Application language | Python |
| API framework | Flask |
| Containerization | Docker and Docker Compose |
| Model runtime | Ollama |
| AI model | Qwen 2.5 Coder 3B |
| Target environments | AWS, cloud infrastructure, and Linux |
| Log analysis targets | Docker, Kubernetes, Jenkins, Argo CD, GitHub Actions, Ansible, and applications |

## Architecture

```text
Log Source
    |
    v
Flask API
    |
    v
Log Processing
    |
    v
Sensitive Data Masking
    |
    v
Log Reduction
    |
    v
Ollama / Qwen 2.5 Coder 3B
    |
    v
Structured AI Analysis
```

### Log Sources

The analyzer is designed to work with logs from:

- Docker containers
- Jenkins builds
- Argo CD applications
- GitHub Actions workflows
- Kubernetes workloads
- Ansible executions
- Linux systems
- Applications

Source-specific collection and integration capabilities are being expanded as part of the project roadmap.

### Sensitive Data Protection

Before sending logs to the AI model, the application masks sensitive information, including:

- AWS access keys
- AWS secret keys
- Passwords
- Tokens
- Bearer tokens
- GitHub tokens
- Private keys

Sensitive data masking is an important protection layer, but it should not be treated as a guarantee that every secret will be detected.

### Intelligent Log Reduction

To reduce processing time and resource consumption, the application prioritizes log lines containing indicators such as:

```text
ERROR
FATAL
EXCEPTION
FAILED
TIMEOUT
OOMKilled
CrashLoopBackOff
ImagePullBackOff
Connection refused
Permission denied
HTTP 500–504
```

Surrounding context lines are retained to preserve information that may help explain an error.

### AI Analysis Output

The model receives:

- Log statistics
- Repeated error patterns
- Important log lines
- Source information
- Relevant context

The response is organized into:

1. Root Cause
2. Evidence from Logs
3. Impact
4. Recommended Fix
5. Verification Steps
6. Prevention

The prompt instructs the model not to invent a root cause when the available evidence is insufficient.

## Running and Verifying

The commands below reflect the Docker Compose service name and application port used during development.

### Build and Start

From the project directory:

```bash
docker compose build ai-log-analyzer
docker compose up -d
```

### View Application Logs

```bash
docker compose logs --tail=100 ai-log-analyzer
```

### Verify Application Health

```bash
curl http://localhost:5001/health
```

### Validate Python Syntax

Before rebuilding after Python code changes:

```bash
python3 -m py_compile app.py
```

### Rebuild Without Cache

During troubleshooting, a clean rebuild was performed using:

```bash
docker compose build --no-cache ai-log-analyzer
docker compose up -d
```

### Ollama Connectivity

Ollama was tested independently of Flask through its generation endpoint:

```text
http://ollama:11434/api/generate
```

A successful response helped isolate the application problem from the Ollama networking and model layers.

The hostname `ollama` refers to the Ollama service within the Docker Compose network.

## Troubleshooting and Performance

### Container Restart Issue

During development, the Flask container repeatedly restarted.

The initial error was:

```text
SyntaxError: invalid syntax
```

The cause was separator text accidentally inserted into the Python source:

```text
=========================
```

After removing the separator, another error appeared:

```text
IndentationError: expected an indented block
```

Several Python functions had lost their required indentation.

### Investigation Workflow

The issue was resolved using the following sequence:

1. Inspect container logs.
2. Identify the Python syntax error.
3. Correct invalid text and indentation.
4. Validate the file with `py_compile`.
5. Rebuild and restart the application.
6. Verify the health endpoint.

```bash
# Inspect the failure
docker compose logs --tail=100 ai-log-analyzer

# Validate the Python file
python3 -m py_compile app.py

# Rebuild after fixing the errors
docker compose build --no-cache ai-log-analyzer

# Start the services
docker compose up -d

# Verify application health
curl http://localhost:5001/health
```

The core troubleshooting principle is:

```text
Validate → Diagnose → Fix → Test → Deploy
```

### Performance Optimizations

The project uses the following techniques to control inference time and resource consumption:

- Limit the size of logs submitted for analysis.
- Reduce unnecessary log lines.
- Retain important errors and nearby context.
- Limit AI output tokens.
- Use `keep_alive` to keep the model loaded.
- Use a lower temperature for more consistent troubleshooting responses.

### Lessons Learned

- Validate application syntax before repeatedly rebuilding containers.
- Test dependencies independently to isolate failures.
- Preserve relevant context when reducing logs.
- Protect sensitive information before AI processing.
- Treat AI-generated findings as hypotheses that require verification.

Traditional investigation remains the foundation:

```text
Logs → Metrics → Events → Configuration → Network → IAM → Application
```

## Roadmap and Author

### Planned Improvements

- [ ] Extend Kubernetes log collection.
- [ ] Integrate Prometheus metrics.
- [ ] Add Grafana dashboards.
- [ ] Implement automated incident detection.
- [ ] Expand Ansible log analysis.
- [ ] Expand GitHub Actions failure analysis.
- [ ] Expand Jenkins pipeline analysis.
- [ ] Expand Argo CD deployment failure analysis.
- [ ] Add more production-style troubleshooting scenarios.

### Author

[Nagarajan S](https://www.linkedin.com/in/nagarajan-s-992545258/)

AWS DevOps Engineer working with Linux, Git, GitHub, Terraform, Docker, Kubernetes, Python, Prometheus, Grafana, GitHub Actions, and Argo CD.

This project brings together cloud infrastructure, containers, CI/CD, GitOps, monitoring, and AI-assisted troubleshooting in a practical DevOps workflow.
