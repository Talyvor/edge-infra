# Database migrations

The platform uses **one shared Postgres database** (the R4 co-location decision):
the control-plane schema (`migrations/0001…0007`) and the OSB schema
(`osb/migrations/0001…0002`) both live in it. `cmd/migrate` applies **both** sets,
idempotently, and must run **before** the control-plane / OSB services start.

`edge-issuer` self-migrates its own separate database on startup; this runner is
the equivalent for the shared DB.

## How it works

`cmd/migrate` embeds both SQL sets (`migrations/embed.go`,
`osb/migrations/embed.go`) and applies each file — control-plane first, then OSB,
lexical order within each — recording every applied file in a `schema_migrations`
table. On a re-run it skips already-recorded files, so **re-running is a no-op**.

Tracking (not `IF NOT EXISTS` guards) is what makes it idempotent: some
control-plane migrations are bare `ALTER TABLE … ADD COLUMN` (0006, 0007) that
error on a second raw apply. Each file is applied and recorded in one transaction
— it either lands and is marked done, or neither happens.

## Kubernetes

Nothing to do — the `edge-control-plane` chart ships a migrate **Job** as a
`pre-install,pre-upgrade` Helm hook (`templates/migrate-job.yaml`, hook-weight
`-5`) that runs the `edge-migrate` image against the shared-DB DSN
(`postgres.existingSecret` / `postgres.secretKey`) before any Deployment rolls
out. A failed migration fails the release (the services never start against a
half-migrated DB).

## Non-Kubernetes (self-host)

The runner is a plain static binary with **no Kubernetes dependency** — the
self-host path is one command. Either run the image:

```
docker run --rm -e DATABASE_URL='postgres://user:pass@host:5432/edge?sslmode=disable' \
  ghcr.io/talyvor/edge-migrate:<tag>
```

or the binary directly:

```
DATABASE_URL='postgres://user:pass@host:5432/edge?sslmode=disable' go run ./cmd/migrate
```

Run it once before starting the services, and again on every upgrade (it is safe
to run every boot). It exits non-zero if any migration fails.

## Adopting the runner on an ALREADY-migrated database

On a **fresh** database the runner applies everything and records it. On a
database that was migrated **manually/by an older deploy** (schema present, but no
`schema_migrations` table), the runner would try to re-apply 0001…0007 and fail on
the non-idempotent `ADD COLUMN` migrations. Adopt it with a one-time baseline:

```
DATABASE_URL='...' edge-migrate baseline
```

`baseline` records the already-applied filenames in `schema_migrations` **without
running any SQL**, so the subsequent normal `migrate` is a no-op. It is guarded:

- it **refuses** if `schema_migrations` already has rows (the DB is already
  adopted — use the normal runner); and
- it **refuses** unless the DB is at the **current** schema (a probe checks the
  latest CP + OSB migration effects are present), so it can never mark a
  genuinely-missing migration as applied — a partially-migrated DB must be brought
  up with the normal `migrate` first.

A genuinely-new migration added *after* a baseline is still applied normally by
the next `migrate` (baseline only records the files present at adoption time).
