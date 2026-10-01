# SENTINEL

Internal fraud detection and investigation demo. SENTINEL uses deterministic rules and generated transaction data; it does not connect to a bank or use machine learning.

## Start locally

The workspace uses a Python virtual environment at `.venv/` and Node.js/npm.

```sh
npm install
".venv/bin/python" -m pip install -r backend/requirements.txt
npm run dev:full
```

Open the Vite URL printed in the terminal (normally `http://localhost:5173`). The API is available at `http://localhost:8000`, with interactive endpoint docs at `/docs`.

To run either process separately, use `npm run api` and `npm run dev` in separate terminals. Run the integration tests with `npm run test:api` and the frontend build with `npm run build`.

## Demo access

Analyst: `analyst@sentinel.local` / `sentinel-demo`

Administrator: `admin@sentinel.local` / `sentinel-admin`

Generate the demo dataset from the dashboard. It creates five profiles and 60 deterministic transactions across baseline, high amount, velocity, impossible travel, and multiple-signal scenarios. Run an individual profile analysis or analyze all profiles, open an alert to inspect evidence, then mark it reviewed or clear it. Data persists in `backend/sentinel.db`.

## Included

- SQLite-backed users, transactions, rule results, fraud flags, reviews, and audit history
- JWT access tokens and bcrypt password hashing
- Velocity, historical-median amount, and Haversine geography rules
- Dashboard, profile explorer, transaction ledger, alert queue, evidence drawer, review flow, rule controls, and admin activity log
- Responsive analyst console with risk-level and status indicators

## AWS SES notifications

When analysis flags transactions for a user, SENTINEL sends one server-side SES email after that user's first successful delivery. The message includes the public user ID and triggered-rule evidence in both HTML and plain text. Later flagged transactions for that user are recorded as skipped to prevent inbox flooding. SNS is disabled for now.

Copy `backend/.env.example` to `backend/.env` and configure the sender, recipient, and region locally. The active `.env` file is git-ignored. AWS credentials must be available to boto3 through local environment credentials, an AWS profile/SSO session, or an IAM role. Do not commit AWS keys or paste them into chat.

The SES sender identity must be verified in `AWS_REGION`. If the SES account is in its sandbox, verify the recipient address too. Grant the IAM identity `ses:SendEmail` permission for the sender identity. SENTINEL records SES as `mocked` when sender/recipient settings are missing and records a safe AWS error code when sending fails.

The default JWT secret and seeded credentials are for local use only. Set `JWT_SECRET_KEY` to a strong local secret and provision real staff accounts before exposing the service beyond a trusted development environment. PostgreSQL deployment is not configured in this demo.
