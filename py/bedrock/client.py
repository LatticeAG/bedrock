"""HTTP client SDK (spec §8.2). Mirrors src/client.ts: one-to-one wrappers
around the §7 routes; typed ApiError; no reusable ALLOW token."""
from __future__ import annotations

import urllib.error
import urllib.request

from .canon import canonical_string, parse_json_bytes


class ApiError(Exception):
    def __init__(self, status: int, code: str, retryable: bool, audit_seq):
        super().__init__(f"{code} (HTTP {status})")
        self.status = status
        self.code = code
        self.retryable = retryable
        self.audit_seq = audit_seq


class BedrockClient:
    def __init__(self, endpoint: str, credential: str, timeout_ms: int = 10000):
        self.endpoint = endpoint.rstrip("/")
        self.credential = credential
        self.timeout_ms = timeout_ms

    def _fetch(self, method: str, path: str, body=None):
        data = None if body is None else canonical_string(body).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint + path, data=data, method=method,
            headers={
                "authorization": f"Bearer {self.credential}",
                **({"content-type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout_ms / 1000
            ) as res:
                raw = res.read()
                status = res.status
        except urllib.error.HTTPError as e:
            raw = e.read()
            status = e.code
        parsed = parse_json_bytes(raw) if raw else None
        if status >= 400:
            err = (parsed or {}).get("error", {}) if isinstance(parsed, dict) else {}
            raise ApiError(
                status, err.get("code", "AUDIT_UNAVAILABLE"),
                err.get("retryable", False), err.get("audit_seq"),
            )
        return status, parsed

    def readyz(self):
        return self._fetch("GET", "/v1/readyz")[1]

    def charter_validate(self, bundle):
        return self._fetch("POST", "/v1/charter/validate", {"bundle": bundle})[1]

    def charter_publish(self, request_id, bundle):
        return self._fetch(
            "POST", "/v1/charter/publish", {"request_id": request_id, "bundle": bundle}
        )[1]

    def charter_versions(self, after=0, limit=100):
        return self._fetch("GET", f"/v1/charter/versions?after={after}&limit={limit}")[1]

    def charter_version(self, version: int):
        return self._fetch("GET", f"/v1/charter/versions/{version}")[1]

    def deployment(self):
        return self._fetch("GET", "/v1/deployment")[1]

    def pin(self, update):
        return self._fetch("POST", "/v1/deployment/pin", update)[1]

    def pause(self, req):
        return self._fetch("POST", "/v1/deployment/pause", req)[1]

    def check(self, request):
        return self._fetch("POST", "/v1/gateway/check", request)[1]

    def call(self, request):
        status, body = self._fetch("POST", "/v1/gateway/call", request)
        return status, body

    def call_result(self, request_id: str):
        return self._fetch("GET", f"/v1/gateway/calls/{request_id}")

    def dispute(self, req):
        return self._fetch("POST", "/v1/disputes", req)[1]

    def disputes(self, after_seq=0, limit=100):
        return self._fetch("GET", f"/v1/disputes?after_seq={after_seq}&limit={limit}")[1]

    def heartbeat(self, hb):
        return self._fetch("POST", "/v1/fleet/heartbeat", hb)[1]

    def fleet(self):
        return self._fetch("GET", "/v1/fleet")[1]

    def audit(self, after_seq: int, through_seq: int, limit=100):
        return self._fetch(
            "GET",
            f"/v1/audit?after_seq={after_seq}&through_seq={through_seq}&limit={limit}",
        )[1]

    def checkpoint(self, through_seq=None):
        q = "" if through_seq is None else f"?through_seq={through_seq}"
        return self._fetch("GET", f"/v1/audit/checkpoint{q}")[1]

    def metrics(self):
        return self._fetch("GET", "/v1/metrics")[1]
