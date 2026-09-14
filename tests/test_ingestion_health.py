from datetime import UTC, datetime, timedelta

import pytest

from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.incident_service import IncidentService
from incident_investigation_agent.services.ingestion_delivery_service import IngestionDeliveryService


def test_empty_health_and_authentication(client, monkeypatch):
    response = client.get('/ingestion-deliveries/health')
    assert response.status_code == 200
    health = response.json()
    assert health['healthy'] is True
    assert len(health['sources']) == 3
    assert all(row['deliveries'] == 0 and row['average_latency_ms'] is None for row in health['sources'])
    assert client.get('/ingestion-deliveries/health', headers={'authorization': 'Bearer invalid'}).status_code == 401
    assert client.get('/ingestion-deliveries/health', headers={'authorization': 'Bearer test-audit-read-key'}).status_code == 200
    monkeypatch.setattr(settings, 'ingestion_audit_read_api_key', None)
    monkeypatch.setattr(settings, 'ingestion_audit_replay_api_key', None)
    assert client.get('/ingestion-deliveries/health').status_code == 503


def test_windowed_health_replays_latency_and_independent_purges(client, db_session):
    audit = IngestionDeliveryService(IncidentService(IncidentRepository(db_session)))
    now = datetime.now(UTC)

    def delivery(status, *, age_minutes=5, replay_of=None, latency_ms=2000):
        record = audit.begin(source='prometheus-alertmanager', body=b'{}', payload_json={}, replay_of_id=replay_of)
        record.created_at = now - timedelta(minutes=age_minutes)
        record.status = status
        record.completed_at = record.created_at + timedelta(milliseconds=latency_ms) if status != 'processing' else None
        db_session.commit()
        return record

    original = delivery('failed')
    delivery('succeeded', replay_of=original.id)
    delivery('failed', replay_of=original.id)
    delivery('processing')
    old = delivery('failed', age_minutes=120)
    old.payload_expires_at = now - timedelta(minutes=1)
    db_session.commit()
    response = client.get('/ingestion-deliveries/health?minimum_completed=3&latency_threshold_ms=1500')
    assert response.status_code == 200
    health = response.json()
    row = next(row for row in health['sources'] if row['source'] == 'prometheus-alertmanager')
    assert row['deliveries'] == 4
    assert row['failed'] == 2
    assert row['processing'] == 1
    assert row['failure_rate'] == pytest.approx(2 / 3)
    assert row['replay_attempts'] == 2
    assert row['replay_succeeded'] == row['replay_failed'] == 1
    assert row['payload_purges'] == 1
    assert row['latency_samples'] == 3
    assert row['average_latency_ms'] == pytest.approx(2000, abs=1)
    assert row['maximum_latency_ms'] == pytest.approx(2000, abs=1)
    assert {alert['kind'] for alert in health['alerts']} == {'high_failure_rate', 'high_latency', 'replay_failure'}
    assert health['healthy'] is False
    # Purge counts remain stable when monitoring is polled repeatedly.
    again = client.get('/ingestion-deliveries/health?minimum_completed=100').json()
    assert {alert['kind'] for alert in again['alerts']} == {'replay_failure'}
    assert next(row for row in again['sources'] if row['source'] == 'prometheus-alertmanager')['payload_purges'] == 1
    assert 'payload_json' not in str(health)


@pytest.mark.parametrize('query', ['window_minutes=0', 'window_minutes=10081', 'minimum_completed=0', 'failure_rate_threshold=0', 'failure_rate_threshold=2', 'latency_threshold_ms=-1'])
def test_health_rejects_invalid_thresholds(client, query):
    assert client.get('/ingestion-deliveries/health?' + query).status_code == 422
