# Mock OAuth 2 server (Salesforce-like) for PSM-24446

Small test server used to check how Workato's HTTP connector refreshes OAuth 2 tokens.
It issues short-lived access tokens, rotates refresh tokens on every refresh, and answers
any rejected refresh like Salesforce: `400 {"error":"unknown_error","error_description":"retry your request"}`.
`GET /log` shows the real reason for each rejection (old refresh token, missing/wrong client secret, ...).

Endpoints: `GET /authorize`, `POST /token`, `GET /api/data`, `GET /log`, `GET /`.

Env vars: `CLIENT_ID`, `CLIENT_SECRET`, `ACCESS_TTL` (seconds, default 120), `ROTATE` (1/0, default 1), `PORT`.

Run: `python3 mock_oauth_server.py` (Python 3 standard library only).
