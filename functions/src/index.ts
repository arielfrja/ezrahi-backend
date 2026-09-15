import * as functions from 'firebase-functions/v2';
import * as admin from 'firebase-admin';
import { randomBytes } from 'node:crypto';

admin.initializeApp();
const db = admin.firestore();
const auth = admin.auth();

interface CreateOrgPayload {
  /** Optional manual slug; omitted/empty => Firestore auto-ID. */
  orgId?: string;
  name: string;
  adminEmail: string;
  adminPassword?: string;
  licenseStatus: 'ACTIVE' | 'TRIAL' | 'SUSPENDED';
  validUntilDate: string; // ISO String
  maxActiveEvents: number;
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

export const registerOrganization = functions.https.onCall(
  { secrets: [defaultAdminPassword] },
  async (request) => {
  // 1. Verify caller is Super-Admin
  await requireSuperAdmin(request.auth?.uid);

  const data = request.data as CreateOrgPayload;

  // 2. Validate inputs (orgId is optional — manual slug or auto-ID)
  if (!data.name || !data.adminEmail) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing required fields.');
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
  try {
    const existingUser = await auth.getUserByEmail(data.adminEmail);
    adminUid = existingUser.uid;
  } catch (error: unknown) {
    if (
      typeof error === 'object' && error !== null && 'code' in error &&
      (error as { code: unknown }).code === 'auth/user-not-found'
    ) {
      const tempPassword = fallbackPassword(data.adminPassword);
      const newUser = await auth.createUser({
        email: data.adminEmail,
        password: tempPassword,
        displayName: `${data.name} Admin`,
      });
      adminUid = newUser.uid;
    } else {
      const message = error instanceof Error ? error.message : 'Unknown auth error';
      throw new functions.https.HttpsError('internal', message);
    }
  }

  // 5. Write Organization document to Firestore (no stored orgId field —
  //    the Document ID is the single source of truth)
  const newOrg = {
    name: data.name,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    orgAdmins: [adminUid],
    license: {
      status: data.licenseStatus || 'ACTIVE',
      validUntil: admin.firestore.Timestamp.fromDate(new Date(data.validUntilDate)),
      maxActiveEvents: data.maxActiveEvents || 5,
    },
    defaults: {
      roles: ['manager', 'medic', 'security', 'guide', 'tail'],
      reportTypes: ['MEDICAL', 'SECURITY', 'DELAY', 'HAZARD', 'LOGISTICS'],
    },
  };

  await orgRef.set(newOrg);

  return { success: true, orgId: finalOrgId, adminUid };
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
