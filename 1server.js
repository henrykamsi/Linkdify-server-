import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fetch from 'node-fetch';
import admin from 'firebase-admin';
import cron from 'node-cron';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { parseApkMeta } from 'apk-meta-parser';

/* ============================================================
   FIREBASE INIT
   ============================================================ */
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

/* ============================================================
   APP SETUP
   ============================================================ */
const app = express();
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '500mb' }));
app.set('trust proxy', 1);

const PORT = process.env.PORT || 10000;

/* ============================================================
   RATE LIMITING
   ============================================================ */
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many requests. Please slow down.' }
});

const uploadLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body?.developer || req.ip,
  message: { error: 'Upload limit reached. Max 5 per day per developer.' }
});

app.use(generalLimiter);

/* ============================================================
   HELPERS
   ============================================================ */
async function getGitHubConfig() {
  const snap = await db.collection('github_config').where('enabled', '==', true).get();
  if (snap.empty) return null;
  const accounts = [];
  snap.forEach(doc => accounts.push({ id: doc.id, ...doc.data() }));
  accounts.sort((a, b) => (a.createdAt?.seconds || 0) - (b.createdAt?.seconds || 0));
  return accounts[0];
}

async function logActivity(action, details, meta = {}) {
  await db.collection('activity_log').add({
    action,
    details: details || '',
    by: meta.by || 'backend',
    ip: meta.ip || '',
    timestamp: new Date()
  });
}

async function logRequest(req, action) {
  await db.collection('request_log').add({
    action,
    ip: req.ip,
    userAgent: (req.headers['user-agent'] || '').substring(0, 200),
    timestamp: new Date()
  });
}

async function sendWebhooks(event, payload) {
  const cfgSnap = await db.collection('webhook_config').get();
  if (cfgSnap.empty) return;

  const promises = [];
  cfgSnap.forEach(doc => {
    const cfg = doc.data();
    if (!cfg.enabled) return;

    if (cfg.type === 'slack' && cfg.url) {
      promises.push(
        fetch(cfg.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: `*${event}*\n\`\`\`${JSON.stringify(payload, null, 2)}\`\`\``
          })
        }).catch(e => console.warn('Slack failed:', e.message))
      );
    }

    if (cfg.type === 'custom' && cfg.url) {
      promises.push(
        fetch(cfg.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-HGT-Event': event },
          body: JSON.stringify({ event, ...payload })
        }).catch(e => console.warn('Custom failed:', e.message))
      );
    }
  });

  await Promise.all(promises);
}

async function parseApk(buffer) {
  try {
    const meta = await parseApkMeta(new Blob([buffer]));
    return {
      packageName: meta.packageName,
      versionName: meta.versionName,
      versionCode: meta.versionCode,
      appName: meta.label,
      minSdk: meta.minSdkVersion,
      targetSdk: meta.targetSdkVersion,
      permissions: meta.permissions || [],
      fileSize: meta.apkSize
    };
  } catch (e) {
    console.warn('APK parse failed:', e.message);
    return null;
  }
}

async function checkBanList(field, value) {
  if (!value) return false;
  const snap = await db.collection('ban_list')
    .where('field', '==', field)
    .where('value', '==', value)
    .where('active', '==', true)
    .get();
  return !snap.empty;
}

async function checkKillSwitch() {
  try {
    const snap = await db.collection('admin_config').doc('kill_switch').get();
    if (!snap.exists) return false;
    return snap.data().active === true;
  } catch { return false; }
}

async function checkDuplicateHash(hash) {
  const snap = await db.collection('live_apps')
    .where('apkHash', '==', hash)
    .limit(1)
    .get();
  return !snap.empty;
}

/* ============================================================
   ROUTES
   ============================================================ */

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Kill switch check
app.get('/api/kill-switch', async (req, res) => {
  const active = await checkKillSwitch();
  res.json({ active });
});

// GitHub config
app.get('/api/github-config', async (req, res) => {
  try {
    const cfg = await getGitHubConfig();
    if (!cfg) return res.json({ available: false });
    res.json({
      available: true,
      user: cfg.user, repo: cfg.repo, tag: cfg.tag, capacityGB: cfg.capacityGB
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- UPLOAD APK ---------- */
app.post('/api/upload-apk', uploadLimiter, async (req, res) => {
  try {
    // Kill switch
    if (await checkKillSwitch()) {
      return res.status(503).json({ error: 'Store is in maintenance mode.' });
    }

    const { appId, packageName, fileName, fileBase64, developer, developerEmail } = req.body;

    if (!fileName || !fileBase64) return res.status(400).json({ error: 'fileName and fileBase64 required' });

    // Ban list check
    if (await checkBanList('email', developerEmail)) {
      return res.status(403).json({ error: 'You have been banned.' });
    }
    if (await checkBanList('ip', req.ip)) {
      return res.status(403).json({ error: 'Access denied.' });
    }
    if (await checkBanList('package', packageName)) {
      return res.status(403).json({ error: 'This package name is blocked.' });
    }

    const fileBuffer = Buffer.from(fileBase64, 'base64');
    const fileSizeMB = fileBuffer.length / (1024 * 1024);

    if (fileSizeMB > 500) {
      return res.status(400).json({ error: 'File too large. Max limit: 500 MB.' });
    }

    // Duplicate hash check
    const hash = crypto.createHash('md5').update(fileBuffer).digest('hex');
    if (await checkDuplicateHash(hash)) {
      return res.status(409).json({ error: 'This APK has already been uploaded.' });
    }

    // APK metadata
    const meta = await parseApk(fileBuffer);
    if (meta && meta.packageName !== packageName) {
      return res.status(400).json({
        error: `Package name mismatch. APK says "${meta.packageName}" but you entered "${packageName}".`
      });
    }

    // Duplicate package name check
    const dupSnap = await db.collection('live_apps').where('packageName', '==', packageName).limit(1).get();
    if (!dupSnap.empty) {
      return res.status(409).json({ error: 'Package name already exists in store.' });
    }

    // GitHub
    const cfg = await getGitHubConfig();
    if (!cfg) return res.status(503).json({ error: 'No enabled GitHub storage available.' });

    const relRes = await fetch(
      `https://api.github.com/repos/${cfg.user}/${cfg.repo}/releases/tags/${cfg.tag}`,
      { headers: { Authorization: `Bearer ${cfg.token}`, 'User-Agent': 'HGT-Store' } }
    );

    let release;
    if (relRes.status === 404) {
      const createRes = await fetch(
        `https://api.github.com/repos/${cfg.user}/${cfg.repo}/releases`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${cfg.token}`,
            'Content-Type': 'application/json',
            'User-Agent': 'HGT-Store'
          },
          body: JSON.stringify({
            tag_name: cfg.tag, target_commitish: 'main',
            name: `APK Storage ${cfg.tag}`, draft: false, prerelease: false
          })
        }
      );
      release = await createRes.json();
    } else {
      release = await relRes.json();
    }

    if (!release.upload_url) return res.status(500).json({ error: 'GitHub release failed.' });

    const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '-');
    const uploadUrl = release.upload_url.replace('{?name,label}', `?name=${encodeURIComponent(safeName)}`);

    const uploadRes = await fetch(uploadUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${cfg.token}`,
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'HGT-Store'
      },
      body: fileBuffer
    });

    const asset = await uploadRes.json();
    if (!asset.browser_download_url) return res.status(500).json({ error: 'Upload failed.', details: asset });

    // Save to Firebase
    await db.collection('live_apps').doc(appId).set({
      downloadUrl: asset.browser_download_url,
      fileSize: meta?.fileSize || fileBuffer.length,
      permissions: meta?.permissions || [],
      minSdk: meta?.minSdk, targetSdk: meta?.targetSdk,
      apkHash: hash,
      status: 'pending',
      uploadedViaBackend: true,
      uploadedAt: new Date()
    }, { merge: true });

    // Save version history
    await db.collection('version_history').add({
      appId, packageName,
      version: meta?.versionName || '1.0.0',
      downloadUrl: asset.browser_download_url,
      fileSize: fileBuffer.length,
      uploadedAt: new Date()
    });

    await logActivity('apk-uploaded', `${fileName} (${fileSizeMB.toFixed(1)} MB)`, { ip: req.ip });
    await sendWebhooks('apk_uploaded', { appId, fileName, sizeMB: fileSizeMB, developer });

    res.json({
      success: true,
      downloadUrl: asset.browser_download_url,
      size: fileBuffer.length,
      metadata: meta
    });

  } catch (e) {
    console.error('Upload error:', e);
    res.status(500).json({ error: e.message });
  }
});

/* ---------- INSTALL EVENTS (webhook receiver) ---------- */
app.post('/api/install-event', async (req, res) => {
  try {
    const { event, appId, packageName, userId, reason, error } = req.body;
    if (!event || !appId) return res.status(400).json({ error: 'event and appId required' });

    const payload = {
      appId, packageName: packageName || '',
      userId: userId || 'anonymous',
      reason: reason || '', error: error || '',
      timestamp: new Date().toISOString()
    };

    await db.collection('install_events').add({ event, ...payload, timestamp: new Date() });
    await sendWebhooks(`install_${event}`, payload);

    // Track download counter
    if (event === 'success') {
      await db.collection('live_apps').doc(appId).update({
        downloads: admin.firestore.FieldValue.increment(1)
      }).catch(() => {});
    }

    res.json({ received: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- USER ACTIVITY (recently viewed, wishlist, etc.) ---------- */
app.post('/api/user-activity', async (req, res) => {
  try {
    const { userId, action, appId } = req.body;
    if (!userId || !action) return res.status(400).json({ error: 'userId and action required' });

    await db.collection('user_activity').add({
      userId, action, appId: appId || '',
      timestamp: new Date()
    });

    // Recently viewed
    if (action === 'viewed' && appId) {
      const ref = db.collection('user_recent').doc(`${userId}_${appId}`);
      await ref.set({ userId, appId, viewedAt: new Date() });
    }

    // Wishlist
    if (action === 'wishlist-add' && appId) {
      await db.collection('wishlists').doc(`${userId}_${appId}`).set({ userId, appId, addedAt: new Date() });
    }
    if (action === 'wishlist-remove' && appId) {
      await db.collection('wishlists').doc(`${userId}_${appId}`).delete();
    }

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- SEARCH TRACKING ---------- */
app.post('/api/search-log', async (req, res) => {
  try {
    const { query, userId } = req.body;
    if (!query) return res.status(400).json({ error: 'query required' });

    const docId = query.toLowerCase().trim();
    const ref = db.collection('search_log').doc(docId);
    const snap = await ref.get();

    if (snap.exists()) {
      await ref.update({ count: admin.firestore.FieldValue.increment(1), lastSearch: new Date() });
    } else {
      await ref.set({ query: docId, count: 1, firstSearch: new Date(), lastSearch: new Date() });
    }

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- TRENDING / TOP CHARTS ---------- */
app.get('/api/trending', async (req, res) => {
  try {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const snap = await db.collection('install_events')
      .where('event', '==', 'success')
      .where('timestamp', '>', sevenDaysAgo)
      .get();

    const counts = {};
    snap.forEach(doc => {
      const id = doc.data().appId;
      counts[id] = (counts[id] || 0) + 1;
    });

    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 20);
    res.json({ trending: sorted.map(([appId, count]) => ({ appId, installs: count })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/top-charts', async (req, res) => {
  try {
    const snap = await db.collection('live_apps')
      .where('status', '==', 'approved')
      .orderBy('downloads', 'desc')
      .limit(50)
      .get();
    const apps = [];
    snap.forEach(doc => apps.push({ id: doc.id, ...doc.data() }));
    res.json({ apps });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/new-releases', async (req, res) => {
  try {
    const snap = await db.collection('live_apps')
      .where('status', '==', 'approved')
      .orderBy('submittedAt', 'desc')
      .limit(50)
      .get();
    const apps = [];
    snap.forEach(doc => apps.push({ id: doc.id, ...doc.data() }));
    res.json({ apps });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- RECOMMENDATIONS ---------- */
app.get('/api/recommendations/:appId', async (req, res) => {
  try {
    const appRef = await db.collection('live_apps').doc(req.params.appId).get();
    if (!appRef.exists) return res.json({ apps: [] });
    const appData = appRef.data();
    const tags = appData.tags || [];
    const category = appData.category;

    const snap = await db.collection('live_apps')
      .where('status', '==', 'approved')
      .where('category', '==', category)
      .limit(20)
      .get();

    const results = [];
    snap.forEach(doc => {
      if (doc.id === req.params.appId) return;
      const d = doc.data();
      const common = (d.tags || []).filter(t => tags.includes(t)).length;
      results.push({ id: doc.id, ...d, score: common });
    });
    results.sort((a, b) => b.score - a.score);
    res.json({ apps: results.slice(0, 10) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- BULK UPLOAD QUEUE ---------- */
app.post('/api/bulk-queue', async (req, res) => {
  try {
    const { developer, apps } = req.body;
    if (!developer || !Array.isArray(apps)) {
      return res.status(400).json({ error: 'developer and apps[] required' });
    }
    const batchId = crypto.randomBytes(8).toString('hex');
    await db.collection('bulk_queue').doc(batchId).set({
      developer, apps, status: 'pending', createdAt: new Date()
    });
    res.json({ batchId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- VERSION HISTORY ---------- */
app.get('/api/version-history/:appId', async (req, res) => {
  try {
    const snap = await db.collection('version_history')
      .where('appId', '==', req.params.appId)
      .orderBy('uploadedAt', 'desc')
      .get();
    const versions = [];
    snap.forEach(doc => versions.push({ id: doc.id, ...doc.data() }));
    res.json({ versions });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- STATS (for admin) ---------- */
app.get('/api/stats', async (req, res) => {
  try {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const [apps, installs, reviews, users] = await Promise.all([
      db.collection('live_apps').count().get(),
      db.collection('install_events').where('timestamp', '>', today).count().get(),
      db.collection('reviews').count().get(),
      db.collection('user_activity').count().get()
    ]);
    res.json({
      totalApps: apps.data().count,
      installsToday: installs.data().count,
      totalReviews: reviews.data().count,
      activeUsers: users.data().count
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   SCHEDULED JOBS
   ============================================================ */

// Nightly backup at 2 AM
cron.schedule('0 2 * * *', async () => {
  console.log('Running nightly backup...');
  try {
    const backupId = 'backup_' + Date.now();
    const collections = ['live_apps', 'developers', 'reviews', 'activity_log'];
    const backup = {};
    for (const col of collections) {
      const snap = await db.collection(col).get();
      backup[col] = [];
      snap.forEach(doc => backup[col].push({ id: doc.id, ...doc.data() }));
    }
    await db.collection('backups').doc(backupId).set({
      data: JSON.stringify(backup),
      createdAt: new Date(),
      collectionCount: collections.length
    });
    await logActivity('backup-complete', backupId);
  } catch (e) { console.error('Backup failed:', e); }
});

// Hourly trending recalc
cron.schedule('0 * * * *', async () => {
  console.log('Recalculating trending...');
  try {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const snap = await db.collection('install_events')
      .where('event', '==', 'success')
      .where('timestamp', '>', sevenDaysAgo)
      .get();
    const counts = {};
    snap.forEach(doc => {
      const id = doc.data().appId;
      counts[id] = (counts[id] || 0) + 1;
    });
    await db.collection('analytics').doc('trending').set({
      trending: counts, updatedAt: new Date()
    });
  } catch (e) { console.error('Trending failed:', e); }
});

// Daily cleanup — remove trash older than 30 days
cron.schedule('0 3 * * *', async () => {
  console.log('Cleaning old trash...');
  try {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const snap = await db.collection('trash').where('deletedAt', '<', cutoff).get();
    const batch = db.batch();
    snap.forEach(doc => batch.delete(doc.ref));
    await batch.commit();
  } catch (e) { console.error('Cleanup failed:', e); }
});

/* ============================================================
   START
   ============================================================ */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`HGT Backend running on port ${PORT}`);
});