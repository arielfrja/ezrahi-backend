# ezrahi-backend

Firebase backend for the Ezrahi platform (project `ezrahi`):
Cloud Firestore security rules, indexes, Storage rules, and Cloud Functions v2 (Node 22).

## Layout

- `firestore.rules` — source of truth for **deployed** rules. Tier 0
  (`system_admins`) + Tier 1 (`organizations`, incl. `permanent_staff`) on top
  of the Android app rules (`users`/`Users`, `Reports`, `events/...`,
  `activities/...` alias, `app_errors`). Canonical live collection is `events`
  (functional name "Activity"); `activities` mirrors it for work-plan naming —
  no migration required. Event creation requires an ACTIVE org license
  (Task 1.2); quota is enforced server-side in `createEvent`.
- `firestore.indexes.json` — composite indexes (events by orgId+status,
  incidents by severity, participants by role, permanent_staff, app_errors).
- `storage.rules` — GPX tracks under `gpx/` (legacy) + `routes/` (portal
  `routes/{orgId}/{file}.gpx`). Auth baseline; fine-grained auth in Firestore.
- `functions/src/index.ts` — v2 callables + triggers:
  - `registerOrganization` (Task 2.1: org + permanent_staff + setupPasswordLink + rollback)
  - `createEvent` (Task 5.2 license/quota enforcement)
  - `terminateActivity` / `terminateEvent` alias (Task 2.3: COMPLETED + remote stop)
  - `dispatchUrgentIncidentEvents` / `dispatchUrgentIncidentActivities` (Task 2.2: HIGH siren FCM)
  - `listUsers`, `addOrgAdmin`, `removeOrgAdmin` (Tier-0 admin management)

## Deploy

```powershell
firebase deploy --only firestore:rules,firestore:indexes,storage --project ezrahi
firebase deploy --only functions --project ezrahi
```

Pushing to `main`/`master` deploys via GitHub Actions
(`.github/workflows/deploy-functions.yml`) using the
`FIREBASE_SERVICE_ACCOUNT_EZRAHI` secret (Service Account JSON with
Firebase Admin + Cloud Functions Deployer). `FIREBASE_TOKEN` is deprecated
and no longer used (Task 1.1).

## Secrets

`DEFAULT_ADMIN_TEMP_PASSWORD` — fallback temp password for invited admins.
Never in code. Lives in three places:

1. Google Secret Manager (runtime): `firebase functions:secrets:set DEFAULT_ADMIN_TEMP_PASSWORD --project ezrahi`
2. `functions/.secret.local` (gitignored, emulator only): `DEFAULT_ADMIN_TEMP_PASSWORD=<value>`
3. GitHub repo secret `DEFAULT_ADMIN_TEMP_PASSWORD` (backup / CI)

Rotate by setting a new version in Secret Manager and redeploying.
