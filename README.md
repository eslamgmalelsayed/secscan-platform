# SecScan

Authorized, non-destructive web/API security testing — plus an on-network agent
(LAN/WiFi) and a desktop app. One TypeScript monorepo.

## Requirements

- **Node.js 22 or newer** (`node -v`). That's it for the default path — no
  Docker, no Postgres, no `prisma generate`.

## Install & run (easiest — browser)

```bash
npm install
npm run build
npm run serve
```

Then open the printed URL (default `http://127.0.0.1:5173`). The whole app runs
in **one process, in memory** — nothing else to set up. Use the **Quick scan**
box: paste a URL you own and it runs the full non-destructive suite. Drop an
`identities.json` at the repo root to also test logged-in pages and enable the
IDOR/BFLA engine.

## Run as a desktop window

```bash
npm --workspace @secscan/desktop run start
```

(Electron installs automatically with `npm install`; if its download was skipped,
run `npm --workspace @secscan/desktop install` once.)

## Build a Windows installer (.exe)

```bash
npm --workspace @secscan/desktop run dist:win
```

Output: an NSIS installer under `apps/desktop/dist/`. See
`apps/desktop/README.md` for packaging/signing notes. (Must be run on Windows.)

## On-network agent (LAN / WiFi, your own network)

```bash
node packages/cli/dist/secscan.js agent          # devices + ARP-spoof + WiFi posture
node packages/cli/dist/secscan.js services <host>
node packages/cli/dist/secscan.js quick <url>    # one-URL scan
```

## Broadcast a message to your devices

Run with `SECSCAN_HOST=0.0.0.0 npm run serve`, open `/display` on any device on
the network, and use the **Broadcast to devices** box in the console.

## Optional: full stack (Postgres + Redis + worker)

Only if you want persistent history and the queued worker path:

```bash
npm run db:generate -w @secscan/api   # generate the real Prisma client (needs network)
npm run services:up                   # Docker: Postgres + Redis + Mailpit
npm run db:migrate
npm run local -- --full               # API + worker + web, Dockerized
```

## Test

```bash
npm test            # all packages
npm --workspace @secscan/api run smoke
```

## Scope

SecScan tests systems and apps **you own or are authorized to test**,
non-destructively. It does not include tools whose purpose is attacking other
people's systems or software (cracking/bypassing other apps, cutting other
people's network access).

## Assessment projects

Open **Assessment projects** in the web console to plan cases, import evidence,
review observations, assign remediation, retest and publish report snapshots
in Arabic and English. Local project revisions persist in `~/.secscan/projects`.
The shared API uses PostgreSQL when configured. See
[the implementation and acceptance plan](docs/assessment-platform.md) for setup,
supported evidence formats, operator roles and the field pilot.
