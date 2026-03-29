# OCEAN REST API

The OCEAN REST API is exposed when running in server mode (`ocean serve`). It enables external GRC platforms to query evidence and inspect control effectiveness.

Full OpenAPI specification: [contracts/api.yaml](../.specify/specs/ocean-core/contracts/api.yaml)

Endpoints across evidence, controls, modules, and health.

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

All endpoints except `/api/v1/health` require a Bearer token:

```bash
curl -H "Authorization: Bearer <your-token>" http://localhost:8080/api/v1/evidence
```

Set the token when starting the server:

```bash
ocean serve --auth-token "your-secret-token" --port 8080
```

## Pagination

List endpoints use **cursor-based pagination**:

- `limit` (query param): Number of results per page (default: 50, max: 200)
- `cursor` (query param): Opaque cursor from a previous response

Response envelope:

```json
{
  "data": [...],
  "meta": {
    "cursor": "next-page-cursor",
    "limit": 50,
    "has_more": true
  }
}
```

When `has_more` is `false`, you have reached the last page.

---

## Endpoints

### 1. List Evidence

**`GET /api/v1/evidence`**

Query evidence records with optional filters. Results are ordered by collection time descending (newest first).

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `control_id` | string | Filter by control identifier |
| `source` | string | Filter by source system (e.g., okta, aws) |
| `from_time` | string (RFC3339) | Inclusive start of time range |
| `to_time` | string (RFC3339) | Exclusive end of time range |
| `cursor` | string | Pagination cursor |
| `limit` | integer | Results per page (1-200, default 50) |

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/evidence?control_id=iam.mfa_enforcement&limit=10"
```

**Response (200):**

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "control_id": "iam.mfa_enforcement",
      "class_uid": 1001,
      "category_uid": 1,
      "activity_id": 1,
      "time": "2026-01-15T10:30:00Z",
      "confidence_level": "passive_observation",
      "status_id": 1,
      "status": "MFA enforcement is required for all users",
      "metadata": {
        "module": { "name": "mock.test", "version": "0.1.0", "type": "observer" },
        "source": { "system": "mock", "api_version": "v1", "endpoint": "/api/v1/policies" }
      },
    }
  ],
  "meta": { "cursor": "", "limit": 10, "has_more": false }
}
```

### 2. Get Evidence

**`GET /api/v1/evidence/{id}`**

Retrieve a single evidence record by UUID.

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/evidence/550e8400-e29b-41d4-a716-446655440000"
```

**Response (200):**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "control_id": "iam.mfa_enforcement",
    "class_uid": 1001,
    "...": "full evidence record"
  }
}
```

### 3. List Controls

**`GET /api/v1/controls`**

Returns all loaded control definitions.

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/controls"
```

**Response (200):**

```json
{
  "data": [
    {
      "id": "iam.mfa_enforcement",
      "name": "MFA Enforcement Policy",
      "description": "Verifies that MFA is enforced for all user accounts",
      "framework_mappings": [
        { "framework_id": "soc2", "control_ref": "CC6.1" },
        { "framework_id": "iso27001", "control_ref": "A.9.4.2" }
      ],
      "observers": [{ "module_id": "okta.mfa_policy" }],
      "testers": [{ "module_id": "okta.mfa_bypass" }],
      "evaluation_logic": {
        "cel_expression": "effective_count > 0 && ineffective_count == 0 && has_active"
      }
    }
  ],
  "meta": { "limit": 1, "has_more": false }
}
```

### 5. Get Control

**`GET /api/v1/controls/{id}`**

Returns a single control definition by its dotted identifier.

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/controls/iam.mfa_enforcement"
```

### 6. Get Control Status

**`GET /api/v1/controls/{id}/status`**

Returns the latest evaluated effectiveness status for a control.

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/controls/iam.mfa_enforcement/status"
```

**Response (200):**

```json
{
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440000",
    "control_id": "iam.mfa_enforcement",
    "timestamp": "2026-01-15T10:35:00Z",
    "status": "effective",
    "confidence": "high",
    "evidence_ids": [
      "550e8400-e29b-41d4-a716-446655440000",
      "550e8400-e29b-41d4-a716-446655440001"
    ],
    "evaluation_details": "CEL evaluation: expr=..., hash=..., verdict=effective"
  }
}
```

### 7. Get Control History

**`GET /api/v1/controls/{id}/history`**

Returns time-series effectiveness data with uptime percentage calculation.

**Required Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `from` | string (RFC3339) | Start of time range |
| `to` | string (RFC3339) | End of time range |

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/controls/iam.mfa_enforcement/history?from=2026-01-01T00:00:00Z&to=2026-01-15T00:00:00Z"
```

**Response (200):**

```json
{
  "data": {
    "statuses": [
      {
        "control_id": "iam.mfa_enforcement",
        "timestamp": "2026-01-01T10:00:00Z",
        "status": "effective",
        "confidence": "high"
      }
    ],
    "uptime": {
      "control_id": "iam.mfa_enforcement",
      "from": "2026-01-01T00:00:00Z",
      "to": "2026-01-15T00:00:00Z",
      "total_buckets": 14,
      "effective_buckets": 14,
      "ineffective_buckets": 0,
      "gap_buckets": 0,
      "uptime_percent": 100.0
    }
  }
}
```

### 8. List Modules

**`GET /api/v1/modules`**

Returns all registered observer and tester modules with metadata.

**Example:**

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/modules"
```

**Response (200):**

```json
{
  "data": [
    {
      "ID": "mock.test",
      "Name": "Mock Test Observer",
      "Version": "0.1.0",
      "Type": "observer",
      "SourceSystem": "mock"
    },
    {
      "ID": "mock.safety_test",
      "Name": "Mock Safety Test",
      "Version": "0.1.0",
      "Type": "tester",
      "SourceSystem": "mock",
      "SafetyClassification": "safe",
      "EnvironmentScope": "production"
    }
  ],
  "meta": { "limit": 2 }
}
```

### 10. Health Check

**`GET /api/v1/health`**

Health check endpoint. Does NOT require authentication.

**Example:**

```bash
curl http://localhost:8080/api/v1/health
```

**Response (200):**

```json
{
  "status": "ok",
  "version": "0.1.0",
  "time": "2026-01-15T10:30:00Z"
}
```

---

## Error Responses

All errors follow a consistent JSON envelope:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "evidence not found"
  }
}
```

| HTTP Status | Code | Description |
|---|---|---|
| 400 | `BAD_REQUEST` | Invalid request parameters |
| 401 | `UNAUTHORIZED` | Missing or invalid Bearer token |
| 404 | `NOT_FOUND` | Resource does not exist |
| 500 | `INTERNAL_ERROR` | Server-side failure |
