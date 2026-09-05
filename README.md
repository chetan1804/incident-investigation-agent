# Incident Investigation Agent

A FastAPI backend for ingesting incident evidence and producing deterministic investigation summaries.

## Project goal

Build an agentic AI system that helps engineers investigate production incidents by correlating alerts, logs, deployments, service dependencies, and historical evidence.

## Current capabilities

- Create and retrieve incidents.
- Ingest logs, alerts, and deployments with optional source timestamps.
- Reject evidence linked to missing incidents or the wrong service.
- Correlate evidence within configurable incident time windows.
- Rank signals and generate deterministic root-cause candidates with confidence scores.
- Generate structured AI hypotheses and remediation suggestions grounded in ranked signals.
- Persist AI analysis snapshots and collect hypothesis-level operator feedback.
- Manage schema changes with Alembic migrations.

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
5. Create or upgrade the database:
   `alembic upgrade head`
6. Run tests:
   `pytest -q`
7. Start the API:
   `uvicorn --app-dir src incident_investigation_agent.api.app:app --reload`

## Configuration

Environment variables are centralized in the application settings module. Copy the example file before local use:

```bash
cp .env.example .env
```

## Database migrations

For a new database, run `alembic upgrade head`. If you have the legacy database created before migrations were introduced, back it up, run `alembic stamp 20260822_0001`, and then run `alembic upgrade head`.

Create future migrations with:

```bash
alembic revision --autogenerate -m "describe the schema change"
alembic upgrade head
```

Tests use a separate temporary SQLite database and never modify the configured application database.

## Investigation correlation

An incident's `started_at` value anchors its evidence window. The default window includes evidence from 60 minutes before through 30 minutes after that timestamp. Deployments are only considered through the incident start, so a later deployment is not presented as a possible cause.

Override the window per investigation request:

```text
GET /incidents/INC-4001/investigation?lookback_minutes=120&lookahead_minutes=45
```

The defaults can be changed with `CORRELATION_LOOKBACK_MINUTES` and `CORRELATION_LOOKAHEAD_MINUTES`. Confidence values currently use the transparent `deterministic_v1` severity-and-proximity heuristic; they are ranking scores, not statistically calibrated probabilities.

## AI-assisted analysis

Set `OPENAI_API_KEY` to enable AI analysis. `OPENAI_MODEL` defaults to `gpt-5-mini`, and `AI_MAX_RANKED_SIGNALS` limits how much correlated evidence is sent to the model. The provider request uses structured output and `store=false`; generated items are rejected if they cite signal IDs that were not in the ranked evidence.

Request analysis after ingesting evidence:

```text
POST /incidents/INC-4001/ai-analysis?lookback_minutes=120&lookahead_minutes=45
```

Each successful response is persisted with its model, prompt version and SHA-256 hash, correlation window, cited signal IDs, and generated output. Retrieve an incident's analysis history with:

```text
GET /incidents/INC-4001/ai-analyses
```

Record an operator assessment against a zero-based hypothesis index:

```text
POST /ai-analyses/AIA-.../feedback

{
  "hypothesis_index": 0,
  "rating": "accurate",
  "operator_name": "on-call-engineer",
  "comment": "Rollback restored service health."
}
```

Allowed ratings are `accurate`, `partially_accurate`, `inaccurate`, and `uncertain`.

The existing `GET /incidents/{incident_id}/investigation` remains deterministic and does not require an API key. AI confidence values are model judgments, not calibrated probabilities, and remediation suggestions should be reviewed by an operator before execution.

## Next step

Aggregate operator feedback into evaluation metrics and add regression datasets for prompt changes.
