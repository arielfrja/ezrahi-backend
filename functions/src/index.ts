import * as functions from 'firebase-functions/v2';
import { onDocumentCreated } from 'firebase-functions/v2/firestore';
import * as admin from 'firebase-admin';
import { randomBytes } from 'node:crypto';

admin.initializeApp();
const db = admin.firestore();
const auth = admin.auth();

// ---------------------------------------------------------------------------
// Naming note (AGENTS.md §4 + work-plan reconciliation):
// Functional name "Activity" == Firestore collection `events` (canonical,
// shared with the Android field app). The spec-alias collection `activities`
// is accepted by rules/triggers for forward-compat, but all portal code and
// all new functions read/write `events`. Do NOT create a parallel `activities`
// doc without a migration.
// ---------------------------------------------------------------------------

interface CreateOrgPayload {
  /** Optional manual slug; omitted/empty => Firestore auto-ID. */
  orgId?: string;
  /** Legacy portal field. Preferred alias: orgName. */
  name?: string;
  orgName?: string;
  adminEmail: string;
  adminPassword?: string;
  /** New spec fields (Task 2.1). */
  adminFullName?: string;
  adminPhone?: string;
  /** New spec quota fields. */
  maxActivities?: number | null;
  maxActiveEvents?: number | null;
  licenseDurationMonths?: number;
  /** Legacy portal fields. */
  licenseStatus?: 'ACTIVE' | 'TRIAL' | 'SUSPENDED';
  validUntilDate?: string; // ISO String
}

const SLUG_PATTERN = /^[a-z0-9_-]+$/;

async function requireSuperAdmin(callerUid: string | undefined): Promise<void> {
  if (!callerUid) {
    throw new functions.https.HttpsError('unauthenticated', 'User must be logged in.');
  }
  const superAdminDoc = await db.collection('system_admins').doc(callerUid).get();
  if (!superAdminDoc.exists) {
    throw new functions.https.HttpsError('permission-denied', 'Caller is not a super-admin.');
  }
}

async function requireOrgOrSuperAdmin(callerUid: string | undefined, orgId: string): Promise<void> {
  if (!callerUid) {
    throw new functions.https.HttpsError('unauthenticated', 'User must be logged in.');
  }
  const superAdminDoc = await db.collection('system_admins').doc(callerUid).get();
  if (superAdminDoc.exists) return;
  const orgSnap = await db.collection('organizations').doc(orgId).get();
  const admins = (orgSnap.data()?.orgAdmins as string[] | undefined) ?? [];
  if (!admins.includes(callerUid)) {
    throw new functions.https.HttpsError('permission-denied', 'Caller is not an admin of this organization.');
  }
}

// Fallback temp password for invited admins. Value lives in Secret Manager
// (DEFAULT_ADMIN_TEMP_PASSWORD), .secret.local for the emulator, and a GitHub
// secret of the same name — never in code. Rotate via:
//   firebase functions:secrets:set DEFAULT_ADMIN_TEMP_PASSWORD --project ezrahi
const defaultAdminPassword = functions.params.defineSecret('DEFAULT_ADMIN_TEMP_PASSWORD');

/** Explicit password wins; otherwise the managed secret; random as last resort. */
function fallbackPassword(provided?: string): string {
  if (provided) return provided;
  try {
    return defaultAdminPassword.value();
  } catch {
    return randomBytes(18).toString('base64');
  }
}

/**
 * Task 2.1 — registerOrganization (enhanced).
 * Input (union of legacy portal + work-plan spec):
 *   legacy: { name, orgId?, adminEmail, adminPassword?, licenseStatus?, validUntilDate?, maxActiveEvents? }
 *   spec:   { orgName, adminEmail, adminFullName?, adminPhone?, maxActivities?, licenseDurationMonths? }
 * Logic: get-or-create Auth user -> create organizations/{orgId} -> create
 *   permanent_staff/{adminUid} -> generatePasswordResetLink (setup link).
 *   Rollback: if any Firestore write fails after creating a NEW Auth user,
 *   delete that Auth user.
 * Output: { success, orgId, adminUid, setupPasswordLink }
 */
export const registerOrganization = functions.https.onCall(
  { secrets: [defaultAdminPassword] },
  async (request) => {
  // 1. Verify caller is Super-Admin
  await requireSuperAdmin(request.auth?.uid);

  const data = request.data as CreateOrgPayload;

  // 2. Normalize inputs (both naming schemes)
  const orgName = (data.orgName ?? data.name ?? '').trim();
  const adminEmail = (data.adminEmail ?? '').trim();
  if (!orgName || !adminEmail) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing required fields (orgName/name, adminEmail).');
  }
  const quotaRaw = data.maxActivities ?? data.maxActiveEvents;
  if (
    quotaRaw !== undefined && quotaRaw !== null &&
    (typeof quotaRaw !== 'number' || quotaRaw < 0)
  ) {
    throw new functions.https.HttpsError('invalid-argument', 'maxActivities/maxActiveEvents must be null or >= 0 (0 = unlimited).');
  }
  // Resolve license expiry: explicit validUntilDate wins; otherwise
  // licenseDurationMonths (spec) or 12-month default.
  let validUntil: Date;
  if (data.validUntilDate) {
    validUntil = new Date(data.validUntilDate);
    if (Number.isNaN(validUntil.getTime())) {
      throw new functions.https.HttpsError('invalid-argument', 'validUntilDate is not a valid date.');
    }
  } else {
    const months = data.licenseDurationMonths ?? 12;
    if (typeof months !== 'number' || months <= 0 || months > 120) {
      throw new functions.https.HttpsError('invalid-argument', 'licenseDurationMonths must be 1..120.');
    }
    validUntil = new Date();
    validUntil.setMonth(validUntil.getMonth() + months);
  }

  // 3. Resolve the document reference: manual slug or auto-ID
  let orgRef: admin.firestore.DocumentReference;
  let finalOrgId: string;
  const manualSlug = data.orgId?.trim().toLowerCase();
  if (manualSlug) {
    if (!SLUG_PATTERN.test(manualSlug)) {
      throw new functions.https.HttpsError(
        'invalid-argument',
        'orgId must match /^[a-z0-9_-]+$/.'
      );
    }
    const candidateRef = db.collection('organizations').doc(manualSlug);
    const existingOrg = await candidateRef.get();
    if (existingOrg.exists) {
      throw new functions.https.HttpsError(
        'already-exists',
        `Organization ID ${manualSlug} already exists.`
      );
    }
    orgRef = candidateRef;
    finalOrgId = manualSlug;
  } else {
    orgRef = db.collection('organizations').doc();
    finalOrgId = orgRef.id;
  }

  // 4. Create or retrieve Org Admin Auth User
  let adminUid: string;
  let createdNewUser = false;
  try {
    const existingUser = await auth.getUserByEmail(adminEmail);
    adminUid = existingUser.uid;
  } catch (error: unknown) {
    if (
      typeof error === 'object' && error !== null && 'code' in error &&
      (error as { code: unknown }).code === 'auth/user-not-found'
    ) {
      const tempPassword = fallbackPassword(data.adminPassword);
      const displayName = data.adminFullName?.trim() || `${orgName} Admin`;
      const newUser = await auth.createUser({
        email: adminEmail,
        password: tempPassword,
        displayName,
        ...(data.adminPhone ? { phoneNumber: undefined } : {}),
      });
      adminUid = newUser.uid;
      createdNewUser = true;
    } else {
      const message = error instanceof Error ? error.message : 'Unknown auth error';
      throw new functions.https.HttpsError('internal', message);
    }
  }

  // 5. Write Organization + permanent_staff with rollback on failure.
  const newOrg = {
    name: orgName,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    orgAdmins: [adminUid],
    license: {
      status: data.licenseStatus || 'ACTIVE',
      validUntil: admin.firestore.Timestamp.fromDate(validUntil),
      // undefined => default 5; 0/null => unlimited (stored as null).
      maxActiveEvents: quotaRaw === undefined
        ? 5
        : (quotaRaw === 0 ? null : quotaRaw),
    },
    defaults: {
      roles: ['manager', 'medic', 'security', 'guide', 'tail'],
      reportTypes: ['MEDICAL', 'SECURITY', 'DELAY', 'HAZARD', 'LOGISTICS'],
    },
  };

  const staffDoc = {
    name: data.adminFullName?.trim() || `${orgName} Admin`,
    phone: data.adminPhone?.trim() || '',
    email: adminEmail,
    defaultRole: 'manager',
    active: true,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };

  try {
    await orgRef.set(newOrg);
    await orgRef.collection('permanent_staff').doc(adminUid).set(staffDoc, { merge: true });
  } catch (error: unknown) {
    if (createdNewUser) {
      try {
        await auth.deleteUser(adminUid);
      } catch {
        // Rollback best-effort: Auth user orphaned — surface original error.
      }
    }
    const message = error instanceof Error ? error.message : 'Failed to write organization.';
    throw new functions.https.HttpsError('internal', message);
  }

  // 6. Setup link for the admin's first login (password set).
  let setupPasswordLink = '';
  try {
    setupPasswordLink = await auth.generatePasswordResetLink(adminEmail);
  } catch {
    setupPasswordLink = '';
  }

  return { success: true, orgId: finalOrgId, adminUid, setupPasswordLink };
});

// ---------------------------------------------------------------------------
// Organization admins management (Tier 0 only)
// ---------------------------------------------------------------------------

export interface AdminUserInfo {
  uid: string;
  email: string;
  displayName: string;
}

/** List Firebase Auth users (candidates for org-admin assignment). */
export const listUsers = functions.https.onCall(async (request): Promise<{ users: AdminUserInfo[] }> => {
  await requireSuperAdmin(request.auth?.uid);

  const users: AdminUserInfo[] = [];
  let pageToken: string | undefined;
  do {
    const page = await auth.listUsers(1000, pageToken);
    for (const u of page.users) {
      users.push({ uid: u.uid, email: u.email ?? '', displayName: u.displayName ?? '' });
    }
    pageToken = page.pageToken;
  } while (pageToken);

  return { users };
});

interface AddOrgAdminPayload {
  orgId: string;
  email: string;
  tempPassword?: string;
}

/**
 * Add an org admin: uses the existing Auth user when the email is known,
 * otherwise creates (invites) a new Auth user, then unions the UID into
 * /organizations/{orgId}.orgAdmins.
 */
export const addOrgAdmin = functions.https.onCall(
  { secrets: [defaultAdminPassword] },
  async (request) => {
  await requireSuperAdmin(request.auth?.uid);
  const data = request.data as AddOrgAdminPayload;

  if (!data.orgId || !data.email) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing orgId or email.');
  }

  const orgRef = db.collection('organizations').doc(data.orgId);
  const orgSnap = await orgRef.get();
  if (!orgSnap.exists) {
    throw new functions.https.HttpsError('not-found', `Organization ${data.orgId} not found.`);
  }

  let uid: string;
  let created = false;
  try {
    uid = (await auth.getUserByEmail(data.email)).uid;
  } catch (error: unknown) {
    if (
      typeof error === 'object' && error !== null && 'code' in error &&
      (error as { code: unknown }).code === 'auth/user-not-found'
    ) {
      const newUser = await auth.createUser({
        email: data.email,
        password: fallbackPassword(data.tempPassword),
        displayName: `${(orgSnap.data()?.name as string) ?? data.orgId} Admin`,
      });
      uid = newUser.uid;
      created = true;
    } else {
      const message = error instanceof Error ? error.message : 'Unknown auth error';
      throw new functions.https.HttpsError('internal', message);
    }
  }

  await orgRef.update({ orgAdmins: admin.firestore.FieldValue.arrayUnion(uid) });
  return { success: true, uid, email: data.email, created };
});

interface RemoveOrgAdminPayload {
  orgId: string;
  uid: string;
}

/** Remove a UID from /organizations/{orgId}.orgAdmins (never the last one). */
export const removeOrgAdmin = functions.https.onCall(async (request) => {
  await requireSuperAdmin(request.auth?.uid);
  const data = request.data as RemoveOrgAdminPayload;

  if (!data.orgId || !data.uid) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing orgId or uid.');
  }

  const orgRef = db.collection('organizations').doc(data.orgId);
  const orgSnap = await orgRef.get();
  if (!orgSnap.exists) {
    throw new functions.https.HttpsError('not-found', `Organization ${data.orgId} not found.`);
  }

  const admins = (orgSnap.data()?.orgAdmins as string[]) ?? [];
  if (admins.length <= 1 && admins.includes(data.uid)) {
    throw new functions.https.HttpsError(
      'failed-precondition',
      'Cannot remove the last admin of an organization.'
    );
  }

  await orgRef.update({ orgAdmins: admin.firestore.FieldValue.arrayRemove(data.uid) });
  return { success: true, uid: data.uid };
});

// ---------------------------------------------------------------------------
// Task 2.3 — terminateActivity / terminateEvent (P1).
// Input (onCall): { eventId | actId, collection?: 'events' | 'activities' }
// Logic: verify caller is super-admin, owning-org admin, or event manager;
//   set status COMPLETED; flip all participants to isTracking:false + OFFLINE.
// Output: { success, eventId, participantsUpdated }
// ---------------------------------------------------------------------------

interface TerminatePayload {
  eventId?: string;
  actId?: string;
  collection?: 'events' | 'activities';
}

async function terminateEventCore(
  collection: 'events' | 'activities',
  eventId: string,
  callerUid: string | undefined,
): Promise<{ success: boolean; eventId: string; participantsUpdated: number }> {
  if (!callerUid) {
    throw new functions.https.HttpsError('unauthenticated', 'User must be logged in.');
  }
  if (!eventId) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing eventId/actId.');
  }
  const eventRef = db.collection(collection).doc(eventId);
  const eventSnap = await eventRef.get();
  if (!eventSnap.exists) {
    throw new functions.https.HttpsError('not-found', `Event ${eventId} not found in ${collection}.`);
  }
  const eventData = eventSnap.data() ?? {};
  const managerId = eventData['managerId'] as string | undefined;
  const orgId = eventData['orgId'] as string | undefined;

  const isSuper = (await db.collection('system_admins').doc(callerUid).get()).exists;
  const isManager = managerId === callerUid;
  let isOrgAdmin = false;
  if (orgId) {
    const orgSnap = await db.collection('organizations').doc(orgId).get();
    const admins = (orgSnap.data()?.orgAdmins as string[] | undefined) ?? [];
    isOrgAdmin = admins.includes(callerUid);
  }
  if (!isSuper && !isManager && !isOrgAdmin) {
    throw new functions.https.HttpsError('permission-denied', 'Caller may not terminate this event.');
  }

  await eventRef.update({
    status: 'COMPLETED',
    endedAt: admin.firestore.FieldValue.serverTimestamp(),
    endedBy: callerUid,
  });

  // Remote stop: flip every participant + location doc to offline.
  const partsSnap = await eventRef.collection('participants').get();
  const batch = db.batch();
  partsSnap.docs.forEach((d) => {
    batch.set(
      d.ref,
      { isTracking: false, status: 'OFFLINE', updatedAt: admin.firestore.FieldValue.serverTimestamp() },
      { merge: true },
    );
  });
  const locsSnap = await eventRef.collection('locations').get();
  locsSnap.docs.forEach((d) => {
    batch.set(d.ref, { isTracking: false }, { merge: true });
  });
  if (!partsSnap.empty || !locsSnap.empty) {
    await batch.commit();
  }
  return { success: true, eventId, participantsUpdated: partsSnap.size };
}

export const terminateActivity = functions.https.onCall(async (request) => {
  const data = request.data as TerminatePayload;
  const id = data.eventId ?? data.actId ?? '';
  const collection = data.collection ?? 'events';
  return terminateEventCore(collection, id, request.auth?.uid);
});

/** Alias for Android-era naming; identical behavior. */
export const terminateEvent = functions.https.onCall(async (request) => {
  const data = request.data as TerminatePayload;
  const id = data.eventId ?? data.actId ?? '';
  const collection = data.collection ?? 'events';
  return terminateEventCore(collection, id, request.auth?.uid);
});

// ---------------------------------------------------------------------------
// Task 5.2 (server-side license enforcement) — createEvent.
// Input: { orgId, name, managerId, startTime, endTime, route?, center?, radiusM? }
// Logic: caller must be super/org admin; org license ACTIVE + not expired;
//   active-event count < quota (null = unlimited); inherit org defaults.
// Output: { success, eventId }
// ---------------------------------------------------------------------------

interface CreateEventPayload {
  orgId: string;
  name: string;
  managerId: string;
  startTime: string;
  endTime: string;
  gpxPath?: string;
  center?: { lat: number; lng: number };
  radiusM?: number;
}

export const createEvent = functions.https.onCall(async (request) => {
  const data = request.data as CreateEventPayload;
  if (!data.orgId || !data.name || !data.managerId || !data.startTime || !data.endTime) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing orgId/name/managerId/startTime/endTime.');
  }
  await requireOrgOrSuperAdmin(request.auth?.uid, data.orgId);

  const orgSnap = await db.collection('organizations').doc(data.orgId).get();
  if (!orgSnap.exists) {
    throw new functions.https.HttpsError('not-found', `Organization ${data.orgId} not found.`);
  }
  const org = orgSnap.data() ?? {};
  const license = (org['license'] as { status?: string; validUntil?: admin.firestore.Timestamp; maxActiveEvents?: number | null }) ?? {};
  if (license.status !== 'ACTIVE') {
    throw new functions.https.HttpsError('failed-precondition', `Organization license is ${license.status ?? 'missing'} — cannot create events.`);
  }
  const validUntil = license.validUntil?.toDate?.();
  if (validUntil && validUntil.getTime() < Date.now()) {
    throw new functions.https.HttpsError('failed-precondition', 'Organization license has expired.');
  }
  const quota = license.maxActiveEvents ?? null;
  if (quota !== null) {
    const activeSnap = await db
      .collection('events')
      .where('orgId', '==', data.orgId)
      .where('status', '==', 'ACTIVE')
      .limit(quota + 1)
      .get();
    if (activeSnap.size >= quota) {
      throw new functions.https.HttpsError('resource-exhausted', `Active-event quota reached (${quota}).`);
    }
  }

  const start = new Date(data.startTime);
  const end = new Date(data.endTime);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid time window.');
  }

  const defaults = (org['defaults'] as { roles?: string[]; reportTypes?: string[] }) ?? {};
  const eventRef = db.collection('events').doc();
  await eventRef.set({
    orgId: data.orgId,
    name: data.name,
    managerId: data.managerId,
    status: 'PLANNED',
    startTime: admin.firestore.Timestamp.fromDate(start),
    endTime: admin.firestore.Timestamp.fromDate(end),
    route: data.gpxPath
      ? { gpxPath: data.gpxPath }
      : data.center
        ? { center: data.center, radiusM: data.radiusM ?? 2000 }
        : null,
    rolesConfig: null, // portal inherits org defaults client-side; override via update
    inheritedDefaults: {
      roles: defaults.roles ?? ['manager', 'medic', 'security', 'guide', 'tail'],
      reportTypes: defaults.reportTypes ?? ['MEDICAL', 'SECURITY', 'DELAY', 'HAZARD'],
    },
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    createdBy: request.auth?.uid ?? '',
  });
  return { success: true, eventId: eventRef.id };
});

// ---------------------------------------------------------------------------
// Task 2.2 — dispatchUrgentIncident (P0).
// Trigger: onDocumentCreated on events/{eventId}/incidents/{incidentId}
//   (+ spec-alias activities/...). Skips unless severity == 'HIGH'.
//   Resolves handler roles (manager, security, medic, clinic_head), loads
//   FCM tokens from users/{uid} (new) + Users/{uid} (legacy), sends a
//   high-priority siren push (channel urgent_siren_channel).
// ---------------------------------------------------------------------------

const HANDLER_ROLES = new Set(['manager', 'event_manager', 'security', 'medic', 'clinic_head', 'clinic', 'paramedic']);

async function loadTokensFor(uids: string[]): Promise<string[]> {
  const tokens: string[] = [];
  await Promise.all(
    uids.map(async (uid) => {
      try {
        const snap = await db.collection('users').doc(uid).get();
        const d = snap.data() ?? {};
        const arr = d['fcmTokens'];
        const one = d['fcmToken'];
        if (Array.isArray(arr)) {
          for (const t of arr) if (typeof t === 'string' && t) tokens.push(t);
        }
        if (typeof one === 'string' && one) tokens.push(one);
      } catch { /* best-effort */ }
      try {
        const legacy = await db.collection('Users').doc(uid).get();
        const d = legacy.data() ?? {};
        const arr = d['fcmTokens'] ?? d['fcm_tokens'];
        const one = d['fcmToken'] ?? d['fcm_token'];
        if (Array.isArray(arr)) {
          for (const t of arr) if (typeof t === 'string' && t) tokens.push(t);
        }
        if (typeof one === 'string' && one) tokens.push(one);
      } catch { /* best-effort */ }
    }),
  );
  return [...new Set(tokens)];
}

async function dispatchIncident(
  collection: 'events' | 'activities',
  eventId: string,
  incidentId: string,
  incident: Record<string, unknown>,
): Promise<void> {
  const severity = incident['severity'];
  if (severity !== 'HIGH') return; // NORMAL = map marker only, no siren.

  const eventSnap = await db.collection(collection).doc(eventId).get();
  const eventData = eventSnap.data() ?? {};
  const managerId = eventData['managerId'] as string | undefined;

  const partsSnap = await db.collection(collection).doc(eventId).collection('participants').get();
  const handlerUids = new Set<string>();
  if (managerId) handlerUids.add(managerId);
  for (const d of partsSnap.docs) {
    const role = String((d.data()['role'] as string | undefined) ?? '').toLowerCase();
    if (HANDLER_ROLES.has(role)) handlerUids.add(d.id);
  }
  if (handlerUids.size === 0) return;

  const tokens = await loadTokensFor([...handlerUids]);
  if (tokens.length === 0) {
    functions.logger.warn(`dispatchUrgentIncident: HIGH incident ${incidentId} has no FCM tokens.`);
    return;
  }

  const title = String(incident['title'] ?? 'דיווח חירום');
  const category = String(incident['category'] ?? '');
  const message = {
    notification: { title: `🚨 ${title}`, body: category ? `${category} — ${eventData['name'] ?? eventId}` : `${eventData['name'] ?? eventId}` },
    android: {
      priority: 'high' as const,
      notification: { channelId: 'urgent_siren_channel', sound: 'siren', defaultSound: false, priority: 'max' as const },
    },
    apns: { payload: { aps: { sound: 'siren.aiff', badge: 1 } } },
    data: { eventId, incidentId, severity: 'HIGH', category },
    tokens,
  };
  const res = await admin.messaging().sendEachForMulticast(message);
  functions.logger.info(
    `dispatchUrgentIncident: HIGH ${collection}/${eventId}/incidents/${incidentId} -> ${res.successCount}/${tokens.length} sent.`,
  );
}

export const dispatchUrgentIncidentEvents = onDocumentCreated(
  'events/{eventId}/incidents/{incidentId}',
  async (event) => {
    const snap = event.data;
    if (!snap) return;
    await dispatchIncident('events', event.params.eventId, event.params.incidentId, snap.data() ?? {});
  },
);

export const dispatchUrgentIncidentActivities = onDocumentCreated(
  'activities/{actId}/incidents/{incidentId}',
  async (event) => {
    const snap = event.data;
    if (!snap) return;
    await dispatchIncident('activities', event.params.actId, event.params.incidentId, snap.data() ?? {});
  },
);
