# Stow backup dashboard

The dashboard is a Rust/Axum API and a Vite/React web app. The API stores device enrollment, policy revisions, and run reports in SQLite. When AWS session issuance is enabled, the device uses a temporary, prefix-scoped AWS session for direct S3 transfers. The dashboard API accepts small JSON messages.

## Run locally

From the repository root with Rust 1.94.1+ and Node.js 22.12+:

```sh
npm --prefix dashboard/web ci
npm --prefix dashboard/web run build
export STOW_ADMIN_TOKEN="$(openssl rand -hex 32)"
cargo run --locked --manifest-path dashboard/api/Cargo.toml
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787) and enter the token held in `STOW_ADMIN_TOKEN`. The browser keeps the token in memory for the current page. For frontend development, leave the Rust service running and use `npm --prefix dashboard/web run dev`. Vite proxies `/api` to port 8787.

| Environment variable | Purpose |
| --- | --- |
| `STOW_ADMIN_TOKEN` | Required administrator bearer token. Generate a high-entropy value. |
| `STOW_LISTEN` | Bind address, default `127.0.0.1:8787`. |
| `STOW_DB` | SQLite path, default `dashboard/data/stow.sqlite3`. Keep it on a persistent volume. |
| `STOW_WEB_DIR` | Path to the built Vite app, default `dashboard/web/dist`. |
| `STOW_AWS_SESSIONS` | Set to `1` to enable AWS STS. Configure the SDK region and a workload identity that can assume the destination role. |
| `STOW_AWS_EXTERNAL_ID` | Optional external ID sent to STS for a role whose trust policy requires it. |

This first slice uses a local admin token and a single SQLite instance. An internet-facing rollout needs the planned administrator sign-in, TLS ingress, and an AWS isolation and restore pilot. The Stow desktop app pairs from its Dashboard page. Local testing allows an HTTP origin on a literal loopback address such as `http://127.0.0.1:8787`; remote dashboards require HTTPS.

## Run with Docker

Build from the repository root with `docker build -t stow-dashboard:0.3.0 dashboard`, or pull the published image from `registry.wbx.previewbay.com/stow-dashboard:0.3.0` after signing in to the registry.

```sh
export STOW_ADMIN_TOKEN="$(openssl rand -hex 32)"
docker run --rm --name stow-dashboard \
  -p 127.0.0.1:8787:8787 \
  --env STOW_ADMIN_TOKEN \
  --mount type=volume,source=stow-dashboard-data,target=/var/lib/stow \
  registry.wbx.previewbay.com/stow-dashboard:0.3.0
```

Use the same admin token on subsequent starts. The named volume stores the database. If you use a bind mount instead, make the data directory writable by container UID and GID 10001. Configure AWS workload identity and `STOW_AWS_SESSIONS=1` at runtime to issue storage sessions.

## Dashboard workflow

1. In **Storage & policy**, enter the bucket, its region, an optional base prefix, and the destination IAM role ARN. Publish the direct-upload policy and the rules devices will apply.
2. In **Devices**, use **Add device** to create a one-time pairing code with a ten-minute lifetime. Codes can replay with the same token within the original window. The API stores token digests.
3. In the Stow desktop app, open **Dashboard**, enter the site address and pairing code, and select **Connect device**. When the assigned bucket is shown, choose **Use dashboard for backups**. Keep selecting local folders and schedules in Stow.
4. View the device's run history and use **Pause** or **Resume** to control backup sessions. **Revoke** blocks future dashboard access for that device. Already issued AWS credentials can last until their expiration.

## Device API

All paths are relative to `/api/v1`. Send `Content-Type: application/json` for requests with a body. Except for enrollment, authenticate these calls with the device's `Authorization: Bearer …` token.

| Request | JSON fields |
| --- | --- |
| `POST /enrollment/redeem` | `pairingCode`, `deviceToken`. Generate the token on the device with a CSPRNG, for example 32 random bytes encoded as hex. The response returns the device ID. |
| `POST /device/check-in` | `appVersion`, `platform`, `scheduleEnabled`, optional `appliedRevision` and `nextDueAt`. Dates use Unix seconds. |
| `GET /device/policy` | Returns the current revision, destination details, device prefix, and rules. |
| `POST /device/runs` | `runId` (UUID), `trigger` (`manual` or `scheduled`). Reuse the run ID if the response is lost. An accepted run pins its policy. |
| `POST /device/storage-sessions` | `purpose` (`backup`, `verify`, `browse`, or `restore`). Supply the active `runId` for `backup`. Returns temporary AWS credentials, destination identity, and expiry in Unix seconds. |
| `PUT /device/runs/{runId}/snapshot` | `sequence` (positive increasing integer), `phase` (`scanning`, `uploading`, `finished`, `finished_with_errors`, `failed`, or `cancelled`), decimal string counters `filesUploaded`, `filesFailed`, `filesSkipped`, and `bytesDone`, optional `errorCode` and `replayed`. |

## AWS setup

The API calls `AssumeRole` for 900-second sessions. The configured role's base policy must authorize the relevant bucket actions before the session policy narrows access. Set the trust policy to the backend workload identity, with the configured external ID for a cross-account setup. Avoid resource policies that directly grant additional privileges to assumed-role sessions.

A backup session is confined to one device subtree and supports PutObject, multipart management, scoped listings, and the GetObject permission required for completion reconciliation via HEAD. Verify is a prefix-listing session. Browse and restore can list and read versions in the device's current destination. Devices receive no object deletion grants. Configure bucket encryption, versioning, and incomplete multipart cleanup in AWS. For SSE-KMS, enter the key ARN and grant the required KMS operations in the role and key policy. Enter the key ARN with Bucket default when the bucket itself defaults to SSE-KMS. Role ARN, bucket, and prefix syntax are validated on publish, with AWS permission checks taking place at session issuance or on S3 requests.

Run a real AWS isolation canary and recovery drill before use with live backups. Replacement-device recovery grants and access to historical destination revisions are planned.

## Verification

```sh
cargo test --locked --manifest-path dashboard/api/Cargo.toml
npm --prefix dashboard/web run build
```

The Rust tests exercise the JSON API with SQLite and use a local STS endpoint to validate the AssumeRole request and scoped policy. No AWS account is needed for the tests.
