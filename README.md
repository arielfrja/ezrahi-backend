# ezrahi-backend

Firebase backend for the Ezrahi platform (project `ezrahi`):
Cloud Firestore security rules, indexes, and (next) Cloud Functions v2.

## Layout

- `firestore.rules` — merged ruleset: Tier 0 (`system_admins`) + Tier 1
  (`organizations`, incl. `permanent_staff`) additions on top of the Android
  app rules (`Users`, `Reports`, `events/...`, `app_errors`), moved here
  unchanged. This repo is the source of truth for **deployed** rules.
- `firestore.indexes.json` — composite indexes (mirrors Android repo).
- `functions/` — coming next: `registerOrganization` callable (todo TASK 2).

## Deploy

```powershell
firebase deploy --only firestore:rules --project ezrahi
firebase deploy --only firestore:indexes --project ezrahi
firebase deploy --only functions --project ezrahi
```

Pushing to `master` also deploys functions via GitHub Actions
(`.github/workflows/deploy-functions.yml`, needs `FIREBASE_TOKEN` secret).

## Secrets

`DEFAULT_ADMIN_TEMP_PASSWORD` — fallback temp password for invited admins.
Never in code. Lives in three places:

1. Google Secret Manager (runtime): `firebase functions:secrets:set DEFAULT_ADMIN_TEMP_PASSWORD --project ezrahi`
2. `functions/.secret.local` (gitignored, emulator only): `DEFAULT_ADMIN_TEMP_PASSWORD=<value>`
3. GitHub repo secret `DEFAULT_ADMIN_TEMP_PASSWORD` (backup / CI)

Rotate by setting a new version in Secret Manager and redeploying.
