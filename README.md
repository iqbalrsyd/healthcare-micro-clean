# Healthcare Microservices (Clean / Hardened)

## Deskripsi

Sistem layanan kesehatan berbasis microservices menggunakan Python 3.12 + FastAPI. Repository ini adalah **baseline aman** untuk pengujian sistem DevSecOps adaptif — semua celah pada versi `*-vuln` telah dimitigasi, dan deployment memenuhi Pod Security Standard `restricted` (K8s namespace) + Docker `no-new-privileges`.

## Ground Truth

| Atribut | Nilai |
|---------|-------|
| Arsitektur | Microservices |
| Domain | Healthcare |
| Bahasa | Python 3.12 |
| Framework | FastAPI 0.115 |
| Database | PostgreSQL 16 (per service) |
| Deployment | Docker Compose + Kubernetes manifests (PSS `restricted`) |
| Tingkat Keamanan | Hardened (baseline HIPAA) |

## Struktur Layanan

```text
services/
├── common/             # Config validator, security primitives, DB helper
├── auth/               # Autentikasi & authorization (JWT)
├── patient/            # Manajemen data pasien (PHI)
├── appointment/        # Janji temu dokter
└── billing/            # Tagihan dan pembayaran
k8s/                    # Manifests K8s (namespace restricted, NetworkPolicy, PDB, secrets)
tests/                  # Unit + smoke tests
docker-compose.yml      # Hardened local stack
.env.example            # Placeholder env, tidak ada nilai real
```

## Kontrol Keamanan yang Diterapkan

1. **No hardcoded secrets** — semua secret via env (divalidasi `config.py` saat startup: panjang, placeholder, required). `.env` di-ignore, hanya `.env.example` yang di-commit.
2. **SQL injection prevention** — semua query parameterized via SQLAlchemy `text(":name")`. Tidak ada f-string atau string concatenation dalam SQL.
3. **PHI protection** — `audit_access()` mencatat setiap baca/tulis PHI (subject, role, IP, user-agent, outcome). SSN disimpan sebagai SHA-256 hash, response hanya kembalikan `ssn_last4`. PHI tidak pernah masuk ke log error.
4. **Strong authentication** — `bcrypt` (cost default passlib) untuk password, min 12 char, JWT HS256 dengan `iss`, `aud`, `exp`, `nbf`, `jti` claims dan allowlist algoritma.
5. **Service-to-service auth** — header `X-Service-Token` (HMAC compare), independent dari JWT, dapat diganti mTLS di prod.
6. **Role-based authorization** — `require_role("doctor", "nurse", "admin")` dependency pada setiap endpoint, dengan patient hanya boleh akses data miliknya sendiri.
7. **Input validation** — Pydantic v2 dengan field constraints (length, pattern, decimal precision), SSN dinormalisasi lalu divalidasi.
8. **No verbose errors** — 5xx response generik, stack trace hanya di log server saat `NODE_ENV != production`.
9. **Encryption in transit** — DB driver pakai `sslmode=require`; FastAPI bind ke `127.0.0.1` di belakang reverse proxy.
10. **Updated dependencies** — `fastapi==0.115.0`, `pydantic==2.9.2`, `pyjwt==2.9.0`, `sqlalchemy==2.0.35` (tanpa CVE kritis).
11. **Hardened container** — base image pinned by digest, non-root user (`appuser` UID 10000), `tini` init, `HEALTHCHECK`, `read_only` friendly, `cap_drop: ALL`, `no-new-privileges`.
12. **K8s hardening** — namespace berlabel PSS `restricted` (enforce/audit/warn), `runAsNonRoot: true`, `runAsUser` eksplisit per pod, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, `automountServiceAccountToken: false`, dedicated `ServiceAccount` per service, `NetworkPolicy` default-deny + allowlist per service, `PodDisruptionBudget` untuk `auth`.
13. **Dependency isolation** — satu database per service (auth-db, patient-db, appointment-db, billing-db), satu user DB per service.
14. **Payment gateway safety** — `PAYMENT_GATEWAY_KEY` dicek keberadaannya, key tidak pernah di-log, hanya flag `key_present` yang dicatat.

## Cara Menjalankan

```bash
cp .env.example .env   # isi dengan secret dari secret manager
cd services/auth && pip install -r requirements.txt && cd -
docker compose up --build
```

Atau di Kubernetes:

```bash
kubectl apply -f k8s/00-namespace.yaml
# Inject secrets via Sealed Secrets / ESO / Vault — JANGAN apply 50-secrets.example.yaml apa adanya
kubectl apply -f k8s/10-serviceaccount-auth.yaml
kubectl apply -f k8s/11-serviceaccount-patient.yaml
kubectl apply -f k8s/20-deployment-auth.yaml
kubectl apply -f k8s/21-deployment-patient.yaml
kubectl apply -f k8s/22-deployment-appointment.yaml
kubectl apply -f k8s/23-deployment-billing.yaml
kubectl apply -f k8s/30-network-policies.yaml
kubectl apply -f k8s/40-pdb-auth.yaml
```

## Endpoint Utama

- `GET  /health` — health check (per service, no PHI/env leak)
- `POST /auth/register` — registrasi user (admin disabled)
- `POST /auth/login` — login (bcrypt compare, audit log)
- `GET  /auth/verify` — verifikasi JWT
- `POST /patients` — buat pasien (PHI ditulis, di-audit)
- `GET  /patients/{id}` — detail pasien (SSN hanya `ssn_last4`, di-audit)
- `GET  /patients` — daftar pasien (paginated, di-audit)
- `POST /appointments` — buat janji temu (di-audit)
- `GET  /appointments` — daftar janji temu
- `POST /billing/invoice` — buat invoice (di-audit, key only flagged)
- `GET  /invoices` — daftar invoice

## Hasil yang Diharapkan dari Sistem DevSecOps

- **Domain detection:** healthcare
- **Technology detection:** Python, FastAPI, PostgreSQL, Docker, Kubernetes
- **Architecture detection:** microservices
- **Deployment detection:** Docker Compose + Kubernetes
- **Secret scan:** PASS (tidak ada secret terkomit; `.env` di-ignore)
- **SAST (SQLi, command injection, deserialization, weak crypto):** PASS
- **Dependency scan:** PASS (deps up-to-date, tidak ada CVE kritis)
- **Container scan:** PASS (rootless, pinned digest, healthcheck, no-new-privileges)
- **K8s manifest scan:** PASS (PSS restricted, NetworkPolicy, no privileged, dedicated SA, secrets from SecretKeyRef)
- **PHI/HIPAA control coverage:** tinggi (audit log, least privilege, encryption-in-transit, no PHI in logs)
- **Risk score:** rendah
- **Standards coverage:** HIPAA baseline terpenuhi
