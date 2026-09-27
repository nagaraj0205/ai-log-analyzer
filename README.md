# 🤖 AI Log Analyzer

An AI-powered DevOps log analysis application built with **Python Flask, Docker, Ollama, and Qwen2.5-Coder**.

The application allows DevOps engineers to select a running Docker container, retrieve its logs, and analyze them using a locally hosted AI model.

It supports multiple log sources including:

* 🐳 Docker
* ☸️ Kubernetes
* 🔧 Jenkins
* 🐧 Linux/System
* ⚙️ Ansible
* 💻 Application logs
* 🔍 Automatic log-source detection

---

# 🚀 Project Overview

The main goal of this project is to simplify troubleshooting of DevOps infrastructure and applications.

Instead of manually copying logs into an AI tool, the application can:

1. Discover Docker containers.
2. Display running containers.
3. Allow the user to select a container.
4. Retrieve the selected container's logs.
5. Sanitize sensitive information.
6. Detect the log source.
7. Calculate log statistics.
8. Identify repeated errors.
9. Send the sanitized logs to a local Ollama AI model.
10. Generate a structured troubleshooting analysis.
11. Provide safe troubleshooting recommendations.

---

# 🏗️ Architecture

```text
                         Browser
                            │
                            │
                            ▼
                  ┌──────────────────┐
                  │   Flask Web App  │
                  │   Port: 5001     │
                  └────────┬─────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
     Docker Socket                 Ollama API
              │                         │
              ▼                         ▼
     Docker Containers          Qwen2.5-Coder
                                      3B
              │                         │
              └────────────┬────────────┘
                           │
                           ▼
                  AI Log Analysis
                           │
                           ▼
                 Troubleshooting Report
```

---

# 🔄 Application Flow

```text
User opens application
        │
        ▼
Container Dashboard
        │
        ▼
List Docker containers
        │
        ▼
User selects container
        │
        ▼
Retrieve container logs
        │
        ▼
Mask sensitive information
        │
        ▼
Detect log source
        │
        ▼
Calculate statistics
        │
        ▼
Identify repeated errors
        │
        ▼
Send sanitized logs to Ollama
        │
        ▼
Qwen2.5-Coder analyzes logs
        │
        ▼
Apply safety/evidence checks
        │
        ▼
Display AI troubleshooting report
```

---

# 🛠️ Technology Stack

| Technology          | Purpose                       |
| ------------------- | ----------------------------- |
| Python              | Application backend           |
| Flask               | Web application/API           |
| Docker              | Containerization              |
| Docker Compose      | Multi-container orchestration |
| Ollama              | Local AI inference            |
| Qwen2.5-Coder 3B    | AI analysis model             |
| HTML/CSS/JavaScript | Frontend                      |
| Requests            | Ollama API communication      |
| Docker Python SDK   | Container management          |
| Git/GitHub          | Source-code management        |

---

# 📁 Project Structure

```text
ai-log-analyzer/
│
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── templates/
│   ├── index.html
│   ├── containers.html
│   └── analyzer.html
│
├── static/
│   ├── style.css
│   └── script.js
│
└── README.md
```

---

# 🐳 Docker Compose Architecture

The application consists of two primary services:

```text
docker-compose
      │
      ├── ai-log-analyzer
      │       └── Flask application
      │
      └── ollama
              └── Qwen2.5-Coder
```

The Flask application communicates with Ollama using the Docker Compose service name:

```text
http://ollama:11434
```

---

# 🔌 Docker Socket

The Flask container needs access to the Docker daemon so that it can list containers and retrieve their logs.

The Flask service uses:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

This allows the application to communicate with the Docker daemon running on the host.

---

# 🧠 Ollama Configuration

The application uses:

```text
qwen2.5-coder:3b
```

The default Ollama endpoint is:

```text
http://ollama:11434/api/generate
```

The Flask application can also use environment variables:

```text
OLLAMA_URL
OLLAMA_MODEL
MAX_LOG_LENGTH
PORT
```

Example:

```text
OLLAMA_URL=http://ollama:11434/api/generate
OLLAMA_MODEL=qwen2.5-coder:3b
MAX_LOG_LENGTH=12000
PORT=5000
```

---

# 📊 Log Analysis

The application calculates basic statistics before sending logs to the AI model.

It identifies:

* Total non-empty lines
* Error count
* Warning count
* Info count
* Repeated error patterns

Example:

```text
SEVERITY OVERVIEW

Errors: 3
Warnings: 2
Overall severity: High
```

---

# 🔍 Automatic Log Detection

The application automatically detects the likely source of the log.

## Jenkins

Detection examples:

```text
[Pipeline]
Finished: FAILURE
Started by user
Jenkins
```

## Kubernetes

Detection examples:

```text
kubectl
CrashLoopBackOff
ImagePullBackOff
namespace
kubelet
pod
```

## Docker

Detection examples:

```text
docker
docker.sock
docker daemon
container exited
OCI runtime
```

## Linux/System

Detection examples:

```text
systemd
systemctl
kernel
journalctl
segmentation fault
permission denied
```

## Application

Detection examples:

```text
ERROR
WARN
Exception
Stack trace
Traceback
HTTP 500
database connection
SQLException
```

## Ansible

The application also supports Ansible logs.

Examples:

```text
PLAY [Deploy Application] *****************

TASK [Install nginx] **********************

changed: [server01]

fatal: [server02]: FAILED!

PLAY RECAP *******************************

server01 : ok=3 changed=1 unreachable=0 failed=0
server02 : ok=2 changed=0 unreachable=0 failed=1
```

Ansible detection patterns include:

```text
PLAY [
TASK [
PLAY RECAP
ansible-playbook
UNREACHABLE!
FAILED!
fatal: [
changed=
failed=
skipping:
```

---

# 🔐 Sensitive Data Protection

Before logs are sent to the AI model, the application attempts to mask sensitive information.

Examples include:

```text
password
passwd
pwd
token
api_key
secret
Authorization: Bearer
AWS Access Key
connection_string
client_secret
```

Example input:

```text
password=mySecretPassword
```

Becomes:

```text
password=[REDACTED]
```

AWS access keys are also detected:

```text
AKIA****************
```

and replaced with:

```text
[REDACTED_AWS_ACCESS_KEY]
```

---

# 🛡️ AI Safety Controls

The application does not blindly trust the AI response.

Additional checks are performed after the AI response.

The application removes potentially unsafe recommendations such as:

```text
chmod 777
chmod 666
unsafe user modification commands
unsafe Docker socket ownership changes
rm -rf /
```

The application also checks whether the AI is making unsupported assumptions.

For example, if the log only shows:

```text
Database connection timeout
```

the AI should not automatically claim:

```text
The database server is overloaded.
```

Instead, the application encourages evidence-based troubleshooting.

---

# 🤖 AI Response Format

The AI is instructed to return:

```text
SUMMARY

LOG SOURCE

SEVERITY OVERVIEW

IMPORTANT EVENTS

REPEATED PATTERNS

PROBABLE ROOT CAUSE

RECOMMENDED ACTIONS
```

Example:

```text
SUMMARY

The application failed while connecting to the database.
Multiple connection timeout errors were detected.

LOG SOURCE

Application

SEVERITY OVERVIEW

- Errors: 3
- Warnings: 1
- Overall severity: High

IMPORTANT EVENTS

1. Application started.
2. Database connection attempt failed.
3. Connection timeout occurred.

REPEATED PATTERNS

Repeated 3 times:
database connection timeout

PROBABLE ROOT CAUSE

The immediate failure is a database connection timeout.
The underlying cause is not confirmed by the supplied log.

RECOMMENDED ACTIONS

1. Verify database availability.
2. Check the configured database endpoint.
3. Review application and database logs.
4. Check connectivity from the application environment.
```

---

# 🏠 Container Dashboard

The application provides a container dashboard.

Example:

```text
+------------------------------------------------------+
|              AI LOG ANALYZER                         |
+------------------------------------------------------+

Running Containers

--------------------------------------------------------
Container       Image                  Status
--------------------------------------------------------
nginx           nginx:latest           Running
redis           redis:latest           Running
my-api          my-api:latest          Running
ollama          ollama/ollama          Running
--------------------------------------------------------

              [ Select Container ]
```

The user can select a container and retrieve its logs.

---

# 🐳 Container Log Retrieval

The application uses the Docker API to retrieve logs.

Conceptually:

```python
container = docker_client.containers.get(container_id)

logs = container.logs(
    tail=500,
    timestamps=True
)
```

The logs are then passed through the sanitization and analysis pipeline.

---

# 🔗 API Endpoints

## Health Check

```text
GET /health
```

Example response:

```json
{
  "status": "healthy",
  "application": "AI Log Analyzer",
  "model": "qwen2.5-coder:3b"
}
```

---

## Analyze Logs

```text
POST /api/analyze
```

Example:

```json
{
  "log_type": "docker",
  "log_text": "container exited with status 1"
}
```

---

## Container List

```text
GET /containers
```

Returns available Docker containers.

---

## Container Logs

```text
GET /container/<container_id>/logs
```

Returns logs for the selected container.

---

# 💻 Local Setup

Clone the repository:

```bash
git clone https://github.com/nagaraj0205/ai-log-analyzer.git
```

Move into the project:

```bash
cd ai-log-analyzer
```

Start the application:

```bash
docker compose up -d
```

Check running containers:

```bash
docker compose ps
```

---

# 🧠 Download the AI Model

Check available models:

```bash
docker compose exec ollama ollama list
```

If the model is not available:

```bash
docker compose exec ollama ollama pull qwen2.5-coder:3b
```

Test the model:

```bash
docker compose exec ollama ollama run qwen2.5-coder:3b "Hello"
```

---

# 🔄 Rebuild After Code Changes

When Python, HTML, Dockerfile, or dependency changes are made:

```bash
docker compose up -d --build
```

Check the application:

```bash
docker compose ps
```

View logs:

```bash
docker compose logs -f
```

View only the Flask application:

```bash
docker compose logs -f ai-log-analyzer
```

View Ollama logs:

```bash
docker compose logs -f ollama
```

---

# 🩺 Troubleshooting

## Check Flask Container

```bash
docker compose ps
```

Expected:

```text
ai-log-analyzer    Up
ollama             Up
```

---

## Check Ollama

```bash
docker compose exec ollama ollama list
```

---

## Test Ollama API

Run the test from the Flask container:

```bash
docker compose exec ai-log-analyzer python -c "import requests; r=requests.post('http://ollama:11434/api/generate',json={'model':'qwen2.5-coder:3b','prompt':'Hello','stream':False}); print(r.status_code); print(r.text[:1000])"
```

Expected:

```text
200
```

---

# ⚠️ Common Issue: Ollama 404

If Flask reports:

```text
404 Client Error: Not Found
for url: http://ollama:11434/api/generate
```

Check:

```bash
docker compose exec ollama ollama list
```

If the model is missing:

```bash
docker compose exec ollama ollama pull qwen2.5-coder:3b
```

Then test:

```bash
docker compose exec ai-log-analyzer python -c "import requests; r=requests.post('http://ollama:11434/api/generate',json={'model':'qwen2.5-coder:3b','prompt':'Hello','stream':False}); print(r.status_code); print(r.text[:1000])"
```

---

# ⚠️ Common Issue: Python Not Found in Ollama

Do not run:

```bash
docker compose exec ollama python ...
```

The Ollama image may not contain Python.

Instead, run Python API tests from the Flask container:

```bash
docker compose exec ai-log-analyzer python ...
```

---

# 🌐 Access the Application

After starting the containers:

```text
http://localhost:5001
```

If running on an EC2 instance, access:

```text
http://<EC2-PUBLIC-IP>:5001
```

Make sure the EC2 Security Group allows TCP port:

```text
5001
```

---

# 🔒 Security Considerations

This project is designed as a local/internal DevOps troubleshooting tool.

Recommended production practices:

* Do not expose Docker socket unnecessarily.
* Restrict access to the Flask application.
* Use authentication before exposing the dashboard publicly.
* Do not store raw logs containing secrets.
* Continue masking credentials before AI processing.
* Use least-privilege infrastructure permissions.
* Review AI-generated commands before execution.
* Never automatically execute AI-generated commands.
* Avoid exposing Ollama directly to the public internet.

---

# 📈 Future Enhancements

Potential improvements include:

* Kubernetes cluster integration
* EKS pod log retrieval
* Jenkins build log integration
* Ansible playbook execution history
* Real-time log streaming
* Log search and filtering
* Authentication and RBAC
* Historical analysis
* Prometheus metrics
* Grafana dashboards
* Alert integration
* Slack/Teams notifications
* AI-generated incident reports
* Root-cause analysis history
* Multi-container log comparison
* Downloadable troubleshooting reports

---

# 🎯 DevOps Use Cases

This application can be used for troubleshooting:

### Docker

```text
Container startup failures
Application crashes
OCI runtime errors
Container exit codes
```

### Kubernetes

```text
CrashLoopBackOff
ImagePullBackOff
Pod failures
Container errors
Application startup problems
```

### Jenkins

```text
Pipeline failures
Build failures
Deployment failures
Stage failures
```

### Ansible

```text
Failed tasks
Unreachable hosts
Playbook failures
Configuration deployment errors
```

### Linux

```text
systemd failures
Permission errors
Kernel errors
Service failures
```

### Application

```text
HTTP 4xx/5xx
Exceptions
Database errors
Stack traces
Application startup failures
```

---

# 📌 Example End-to-End Scenario

Suppose a Docker container is running a Python application.

The container generates:

```text
2026-09-27 10:20:01 ERROR Database connection failed
2026-09-27 10:20:02 ERROR Database connection timeout
2026-09-27 10:20:03 ERROR Database connection timeout
```

The user:

```text
1. Opens AI Log Analyzer
2. Selects the Docker container
3. Retrieves its logs
4. Clicks Analyze
```

The application:

```text
Docker logs
     ↓
Sensitive-data masking
     ↓
Statistics
     ↓
Repeated-error detection
     ↓
Ollama
     ↓
Qwen2.5-Coder
     ↓
Evidence validation
     ↓
Safety filtering
     ↓
Troubleshooting report
```

The user receives a structured analysis without manually copying logs into an external AI service.

---

# 👨‍💻 Project

GitHub Repository:

https://github.com/nagaraj0205/ai-log-analyzer.git

---

# ⭐ Key Features

```text
✅ Local AI inference
✅ Docker container discovery
✅ Container log retrieval
✅ Jenkins log analysis
✅ Docker log analysis
✅ Kubernetes log analysis
✅ Linux log analysis
✅ Application log analysis
✅ Ansible log analysis
✅ Automatic log-source detection
✅ Sensitive-data masking
✅ Error/warning statistics
✅ Repeated-error detection
✅ Evidence-based root-cause analysis
✅ AI safety filtering
✅ Docker Compose deployment
```

---

# 🏁 Conclusion

AI Log Analyzer combines **DevOps troubleshooting, Docker, Flask, and local AI inference** into a single application.

Instead of manually reviewing large amounts of logs, engineers can select a container, retrieve its logs, and receive an evidence-based troubleshooting report from a locally hosted AI model.

The architecture keeps AI inference local through **Ollama**, while the Flask application provides the web interface and DevOps integration layer.

