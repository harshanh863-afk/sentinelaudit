"""Tests for REST API endpoints using FastAPI TestClient.

Uses a temporary file-based SQLite database to avoid thread-safety issues
with in-memory databases across TestClient threads.
"""

import os
import tempfile
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import get_db
from app.main import app
from app.models import Base, Finding, Project, Scan, Target, User
from app.models.enums import ScanStatus, SeverityLevel

_DB_FILE = os.path.join(tempfile.gettempdir(), "sentinel_audit_test_api.db")
if os.path.exists(_DB_FILE):
    for _ in range(5):
        try:
            os.remove(_DB_FILE)
            break
        except PermissionError:
            import time as _time
            _time.sleep(0.5)

TEST_DATABASE_URL = f"sqlite:///{_DB_FILE}"

engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(bind=engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


class TestCreateScan:
    """POST /api/v1/scans"""

    def test_create_scan_requires_existing_target(self):
        resp = client.post("/api/v1/scans", json={"target_id": str(uuid.uuid4())})
        assert resp.status_code == 404

    def test_create_scan_returns_201(self):
        user = User(email="apiscan@example.com", password_hash="pwd", name="Api")
        project = Project(name="P", owner=user)
        target = Target(url="https://api-test.com", host="api-test.com", project=project)
        db = TestSession()
        db.add(user)
        db.add(project)
        db.add(target)
        db.commit()
        target_id = str(target.id)
        db.close()

        resp = client.post("/api/v1/scans", json={"target_id": target_id})
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "queued"
        assert data["target_id"] == target_id


class TestGetScan:
    """GET /api/v1/scans/{id}"""

    def test_get_nonexistent_scan_returns_404(self):
        resp = client.get(f"/api/v1/scans/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_get_scan_returns_status(self):
        user = User(email="apiget@example.com", password_hash="pwd", name="Api")
        project = Project(name="P", owner=user)
        target = Target(url="https://get-test.com", host="get-test.com", project=project)
        scan = Scan(target=target, status=ScanStatus.RUNNING)
        db = TestSession()
        db.add(user)
        db.add(project)
        db.add(target)
        db.add(scan)
        db.commit()
        scan_id = str(scan.id)
        db.close()

        resp = client.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"


class TestGetScanFindings:
    """GET /api/v1/scans/{id}/findings"""

    def test_get_findings_returns_list(self):
        user = User(email="apifind@example.com", password_hash="pwd", name="Api")
        project = Project(name="P", owner=user)
        target = Target(url="https://find-test.com", host="find-test.com", project=project)
        scan = Scan(target=target)
        f1 = Finding(scan=scan, severity=SeverityLevel.HIGH, passed=False, title="XSS")
        f2 = Finding(scan=scan, severity=SeverityLevel.LOW, passed=True, title="Info")
        db = TestSession()
        for e in [user, project, target, scan, f1, f2]:
            db.add(e)
        db.commit()
        scan_id = str(scan.id)
        db.close()

        resp = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_get_findings_pagination(self):
        user = User(email="apipag@example.com", password_hash="pwd", name="Api")
        project = Project(name="P", owner=user)
        target = Target(url="https://pag-test.com", host="pag-test.com", project=project)
        scan = Scan(target=target)
        db = TestSession()
        db.add(user)
        db.add(project)
        db.add(target)
        db.add(scan)
        for i in range(5):
            db.add(Finding(scan=scan, severity=SeverityLevel.LOW, passed=True, title=f"F{i}"))
        db.commit()
        scan_id = str(scan.id)
        db.close()

        resp = client.get(f"/api/v1/scans/{scan_id}/findings?skip=0&limit=2")
        assert resp.status_code == 200
        assert len(resp.json()) == 2


class TestGetScanReport:
    """GET /api/v1/scans/{id}/report"""

    def test_get_report_returns_json(self):
        user = User(email="apirpt@example.com", password_hash="pwd", name="Api")
        project = Project(name="P", owner=user)
        target = Target(url="https://rpt-test.com", host="rpt-test.com", project=project)
        scan = Scan(target=target, risk_score=45.0)
        db = TestSession()
        for e in [user, project, target, scan]:
            db.add(e)
        db.add(Finding(scan=scan, severity=SeverityLevel.HIGH, passed=False, title="SQLi"))
        db.commit()
        scan_id = str(scan.id)
        db.close()

        resp = client.get(f"/api/v1/scans/{scan_id}/report")
        assert resp.status_code == 200
        data = resp.json()
        assert "title" in data
        assert "findings" in data


class TestTargetHistory:
    """GET /api/v1/targets/{id}/history"""

    def test_get_target_history_returns_scans(self):
        user = User(email="apihis@example.com", password_hash="pwd", name="Api")
        project = Project(name="P", owner=user)
        target = Target(url="https://his-test.com", host="his-test.com", project=project)
        s1 = Scan(target=target, status=ScanStatus.COMPLETED, risk_score=80.0)
        s2 = Scan(target=target, status=ScanStatus.FAILED)
        db = TestSession()
        for e in [user, project, target, s1, s2]:
            db.add(e)
        db.commit()
        target_id = str(target.id)
        db.close()

        resp = client.get(f"/api/v1/targets/{target_id}/history")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_nonexistent_target_returns_404(self):
        resp = client.get(f"/api/v1/targets/{uuid.uuid4()}/history")
        assert resp.status_code == 404
