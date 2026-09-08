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
- Aggregate feedback coverage and accuracy metrics by prompt version or model.
- Run and persist automated prompt regressions against a versioned dataset.
- Correlate time-windowed evidence from upstream and downstream service dependencies.
- Reuse confirmed resolutions from deterministically matched historical incidents.
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

The defaults can be changed with `CORRELATION_LOOKBACK_MINUTES` and `CORRELATION_LOOKAHEAD_MINUTES`. Confidence values currently use the transparent `deterministic_v2` heuristic based on severity, proximity, dependency context, and historical similarity; they are ranking scores, not statistically calibrated probabilities.

## Service dependencies

Register a directed dependency when one service relies on another:

```text
POST /service-dependencies

{
  "service_name": "checkout-service",
  "depends_on_service_name": "payments-service",
  "criticality": "high"
}
```

List both upstream and downstream relationships for a service with
`GET /services/{service_name}/dependencies`. Investigations automatically include
time-windowed logs, alerts, and deployments from directly connected services.
Upstream failures and changes can become root-cause candidates, while downstream
failures are ranked as impact signals and are not presented as causes. Dependency
criticality influences signal ranking.

## Historical incidents

Confirm the root cause and resolution after an incident is resolved:

```text
POST /incidents/INC-3001/resolution

{
  "root_cause": "The payment provider connection pool was undersized.",
  "resolution_summary": "Increased the pool size and restarted workers.",
  "resolution_confirmed_by": "primary-on-call",
  "resolved_at": "2026-09-08T13:00:00Z"
}
```

Future investigations compare their title, summary, alerts, and error logs with
earlier confirmed incidents. Matches include the shared terms, similarity score,
root cause, and confirmed resolution. They are also supplied to AI analysis as
grounded `historical_incident` signals. Tune or disable matching per request with
`historical_similarity_threshold` and `historical_incident_limit`; their defaults
come from `HISTORICAL_SIMILARITY_THRESHOLD` and `HISTORICAL_INCIDENT_LIMIT`.

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

Aggregate feedback into evaluation metrics, optionally scoped to a prompt version or model:

```text
GET /ai-evaluations/metrics?prompt_version=incident_analysis_v1&model=gpt-5-mini
```

`accuracy_score` assigns weights of 1.0 to `accurate`, 0.5 to
`partially_accurate`, and 0.0 to `inaccurate`; `uncertain` feedback is excluded
from that score. `feedback_coverage` measures the fraction of generated
hypotheses that have at least one operator assessment.

Run the configured model and prompt against the bundled baseline dataset:

```text
POST /ai-evaluations/regression-runs?dataset_version=incident_analysis_v1
```

The response records pass/fail status for every case, including missing required
citations and disallowed citations. Runs are persisted with the exact model,
prompt version, and prompt hash. Retrieve recent results with:

```text
GET /ai-evaluations/regression-runs?limit=20
```

Regression datasets live in
`src/incident_investigation_agent/evaluation_datasets/` and are included in the
installed package.

Compare a candidate run with an earlier run of the same dataset:

```text
GET /ai-evaluations/regression-runs/AIR-candidate/comparison?baseline_run_id=AIR-baseline
```

The comparison reports pass-rate changes and the case IDs that regressed,
improved, or remained failing. Runs from different dataset versions cannot be
compared.

Use the quality gate from CI with strict defaults (100% pass rate, no pass-rate
drop, and no regressed cases):

```text
POST /ai-evaluations/regression-runs/AIR-candidate/quality-gate

{
  "baseline_run_id": "AIR-baseline"
}
```

The endpoint returns HTTP 200 when the gate passes and HTTP 412 when it fails.
Its request can override `minimum_pass_rate`, `maximum_pass_rate_drop`, and
`maximum_regressed_cases` when a workflow needs controlled tolerances.

The existing `GET /incidents/{incident_id}/investigation` remains deterministic and does not require an API key. AI confidence values are model judgments, not calibrated probabilities, and remediation suggestions should be reviewed by an operator before execution.

## Next step

Add trace-aware correlation so logs spanning multiple services can be grouped into
a single request path during an investigation.
