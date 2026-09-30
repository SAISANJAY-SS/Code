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

High and critical flags trigger server-side SES email and SNS topic notifications independently. SES includes plain-text and HTML message bodies; SNS receives a plain-text alert. AWS secrets are never stored in the browser or database. Copy `backend/.env.example` to `backend/.env` and enter the values on your machine; that file is ignored by git. Or configure boto3's standard AWS credential provider chain with a local AWS profile or an IAM role in deployment.

```sh
cp backend/.env.example backend/.env
# Edit backend/.env locally; never paste AWS credentials into chat or frontend code.
npm run api
```

Alternatively, configure an AWS CLI profile and set `AWS_PROFILE` instead of adding access keys to the env file. The app accepts `AWS_SES_SENDER` / `ALERT_EMAIL` / `AWS_SNS_TOPIC_ARN`; it also supports the attached reference names `SES_SENDER_EMAIL` / `SES_RECIPIENT_EMAIL` / `SNS_TOPIC_ARN`. SENTINEL-prefixed variables take precedence if both forms are set. Verify the sender identity in SES, and ensure the IAM principal has only `ses:SendEmail` permission for that identity. In the SES sandbox, verify the recipient address too. Set the SNS topic ARN to an existing topic in the same region and grant the IAM principal `sns:Publish` on that topic. Configure topic subscriptions separately. Unconfigured channels are recorded as `mocked`; AWS failures are stored as `failed` without returning credential or provider details to the UI.

The default JWT secret and seeded credentials are for local use only. Set `JWT_SECRET_KEY` to a strong local secret and provision real staff accounts before exposing the service beyond a trusted development environment. PostgreSQL deployment is not configured in this demo.
