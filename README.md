# Incident Investigation Agent

A minimal starting point for an incident investigation platform. This repository begins with a clean project skeleton, centralized settings, and a simple verification flow before any database or AI components are added.

## Project goal

Build an agentic AI system that helps engineers investigate production incidents by correlating alerts, logs, deployments, service dependencies, and historical evidence.

## Current step

This repository is intentionally minimal and focuses on the foundation only.

## Structure

- `src/incident_investigation_agent/` contains the application package.
- `scripts/` contains utility and verification scripts.
- `tests/` contains pytest checks.
- `.env.example` provides environment variable defaults.

## Setup

1. Create a virtual environment:
   `python3 -m venv .venv`
2. Activate it:
   `source .venv/bin/activate`
3. Install dependencies:
   `python -m pip install --upgrade pip`
   `python -m pip install -r requirements.txt`
4. Run the setup verification script:
   `python scripts/verify_setup.py`
5. Run tests:
   `pytest -q`

## Configuration

Environment variables are centralized in the application settings module. Copy the example file before local use:

```bash
cp .env.example .env
```

## Next step

The next step is database design and the core incident models.
