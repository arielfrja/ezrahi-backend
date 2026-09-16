"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.removeOrgAdmin = exports.addOrgAdmin = exports.listUsers = exports.registerOrganization = void 0;
const functions = __importStar(require("firebase-functions/v2"));
const admin = __importStar(require("firebase-admin"));
const node_crypto_1 = require("node:crypto");
admin.initializeApp();
const db = admin.firestore();
const auth = admin.auth();
const SLUG_PATTERN = /^[a-z0-9_-]+$/;
async function requireSuperAdmin(callerUid) {
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
function fallbackPassword(provided) {
    if (provided)
        return provided;
    try {
        return defaultAdminPassword.value();
    }
    catch {
        return (0, node_crypto_1.randomBytes)(18).toString('base64');
    }
}
exports.registerOrganization = functions.https.onCall({ secrets: [defaultAdminPassword] }, async (request) => {
    // 1. Verify caller is Super-Admin
    await requireSuperAdmin(request.auth?.uid);
    const data = request.data;
    // 2. Validate inputs (orgId is optional — manual slug or auto-ID)
    if (!data.name || !data.adminEmail) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields.');
    }
    if (data.maxActiveEvents !== undefined && data.maxActiveEvents !== null &&
        (typeof data.maxActiveEvents !== 'number' || data.maxActiveEvents < 0)) {
        throw new functions.https.HttpsError('invalid-argument', 'maxActiveEvents must be null or >= 0 (0 = unlimited).');
    }
    // 3. Resolve the document reference: manual slug or auto-ID
    let orgRef;
    let finalOrgId;
    const manualSlug = data.orgId?.trim().toLowerCase();
    if (manualSlug) {
        if (!SLUG_PATTERN.test(manualSlug)) {
            throw new functions.https.HttpsError('invalid-argument', 'orgId must match /^[a-z0-9_-]+$/.');
        }
        const candidateRef = db.collection('organizations').doc(manualSlug);
        const existingOrg = await candidateRef.get();
        if (existingOrg.exists) {
            throw new functions.https.HttpsError('already-exists', `Organization ID ${manualSlug} already exists.`);
        }
        orgRef = candidateRef;
        finalOrgId = manualSlug;
    }
    else {
        orgRef = db.collection('organizations').doc();
        finalOrgId = orgRef.id;
    }
    // 4. Create or retrieve Org Admin Auth User
    let adminUid;
    try {
        const existingUser = await auth.getUserByEmail(data.adminEmail);
        adminUid = existingUser.uid;
    }
    catch (error) {
        if (typeof error === 'object' && error !== null && 'code' in error &&
            error.code === 'auth/user-not-found') {
            const tempPassword = fallbackPassword(data.adminPassword);
            const newUser = await auth.createUser({
                email: data.adminEmail,
                password: tempPassword,
                displayName: `${data.name} Admin`,
            });
            adminUid = newUser.uid;
        }
        else {
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
            // undefined => default 5; 0/null => unlimited (stored as null).
            maxActiveEvents: data.maxActiveEvents === undefined
                ? 5
                : (data.maxActiveEvents === 0 ? null : data.maxActiveEvents),
        },
        defaults: {
            roles: ['manager', 'medic', 'security', 'guide', 'tail'],
            reportTypes: ['MEDICAL', 'SECURITY', 'DELAY', 'HAZARD', 'LOGISTICS'],
        },
    };
    await orgRef.set(newOrg);
    return { success: true, orgId: finalOrgId, adminUid };
});
/** List Firebase Auth users (candidates for org-admin assignment). */
exports.listUsers = functions.https.onCall(async (request) => {
    await requireSuperAdmin(request.auth?.uid);
    const users = [];
    let pageToken;
    do {
        const page = await auth.listUsers(1000, pageToken);
        for (const u of page.users) {
            users.push({ uid: u.uid, email: u.email ?? '', displayName: u.displayName ?? '' });
        }
        pageToken = page.pageToken;
    } while (pageToken);
    return { users };
});
/**
 * Add an org admin: uses the existing Auth user when the email is known,
 * otherwise creates (invites) a new Auth user, then unions the UID into
 * /organizations/{orgId}.orgAdmins.
 */
exports.addOrgAdmin = functions.https.onCall({ secrets: [defaultAdminPassword] }, async (request) => {
    await requireSuperAdmin(request.auth?.uid);
    const data = request.data;
    if (!data.orgId || !data.email) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing orgId or email.');
    }
    const orgRef = db.collection('organizations').doc(data.orgId);
    const orgSnap = await orgRef.get();
    if (!orgSnap.exists) {
        throw new functions.https.HttpsError('not-found', `Organization ${data.orgId} not found.`);
    }
    let uid;
    let created = false;
    try {
        uid = (await auth.getUserByEmail(data.email)).uid;
    }
    catch (error) {
        if (typeof error === 'object' && error !== null && 'code' in error &&
            error.code === 'auth/user-not-found') {
            const newUser = await auth.createUser({
                email: data.email,
                password: fallbackPassword(data.tempPassword),
                displayName: `${orgSnap.data()?.name ?? data.orgId} Admin`,
            });
            uid = newUser.uid;
            created = true;
        }
        else {
            const message = error instanceof Error ? error.message : 'Unknown auth error';
            throw new functions.https.HttpsError('internal', message);
        }
    }
    await orgRef.update({ orgAdmins: admin.firestore.FieldValue.arrayUnion(uid) });
    return { success: true, uid, email: data.email, created };
});
/** Remove a UID from /organizations/{orgId}.orgAdmins (never the last one). */
exports.removeOrgAdmin = functions.https.onCall(async (request) => {
    await requireSuperAdmin(request.auth?.uid);
    const data = request.data;
    if (!data.orgId || !data.uid) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing orgId or uid.');
    }
    const orgRef = db.collection('organizations').doc(data.orgId);
    const orgSnap = await orgRef.get();
    if (!orgSnap.exists) {
        throw new functions.https.HttpsError('not-found', `Organization ${data.orgId} not found.`);
    }
    const admins = orgSnap.data()?.orgAdmins ?? [];
    if (admins.length <= 1 && admins.includes(data.uid)) {
        throw new functions.https.HttpsError('failed-precondition', 'Cannot remove the last admin of an organization.');
    }
    await orgRef.update({ orgAdmins: admin.firestore.FieldValue.arrayRemove(data.uid) });
    return { success: true, uid: data.uid };
});
//# sourceMappingURL=index.js.map