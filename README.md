# Security Interview Mini-Challenge

## Description

A security-review exercise for a small Fastify and TypeScript service handling sensitive healthcare-related records. The repository includes the starter service plus threat-model, compliance, exploit-demo, testing, and implementation-decision documents.

## Dependencies

- Node.js compatible with the checked-in TypeScript toolchain and npm.
- Docker Compose for the local Redis option.
- Redis when `USE_REDIS_FOR_SHARES=true`.
- Google Cloud credentials and a configured GCS bucket when `USE_GCS_AUDIT_LOGGING=true`.

## Technologies

TypeScript, Node.js, Fastify, Redis, Google Cloud Storage, Docker Compose, tsx, and the TypeScript compiler.

## Setup

```bash
git clone https://github.com/bryan3342/security-test.git
cd security-test/starter
cp .env.example .env
docker compose up -d redis
npm install
npm run dev
```

By default, shares use memory and audits use console output. Enable Redis or GCS through the documented environment variables only after configuring those services. The sample request identity comes from `x-user-id` and `x-role` headers and is intended for this exercise, not production authentication.

## Features

- Record retrieval, record-sharing, and guidance endpoints.
- Redis-backed share tokens with an in-memory fallback.
- GCS audit export with a console fallback.
- Role and record-access checks in the starter implementation.
- A prompt template for guidance responses.
- Written threat model, compliance mapping, exploit reproduction notes, decisions, and security testing notes.

This is a time-boxed interview exercise and not a production healthcare service.

## Commands to run

```bash
cd starter
npm run dev
npm run build
```

Example requests are in [starter/README.md](starter/README.md). The package defines no automated test command.

## Contributors

- [Bryan Mejia (@bryan3342)](https://github.com/bryan3342), credited in Git history.
- Michael, credited in Git history.
