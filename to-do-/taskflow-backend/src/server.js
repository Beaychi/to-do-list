import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import { initializeApp, applicationDefault, cert } from 'firebase-admin/app';
import { getAuth as getAdminAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { google } from 'googleapis';
import { DateTime } from 'luxon';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin:
      process.env.CORS_ORIGIN?.split(',') || [
        'http://localhost:5500',
        'http://127.0.0.1:5500',
      ],
    credentials: true,
  })
);

// --- Firebase Admin ---
const adminApp = initializeApp({
  credential: process.env.FIREBASE_SERVICE_ACCOUNT
    ? cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
    : applicationDefault(),
});
const db = getFirestore(adminApp);
const adminAuth = getAdminAuth(adminApp);

// --- Auth middleware (expects `Authorization: Bearer <Firebase ID token>`) ---
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing Authorization header' });
    const decoded = await adminAuth.verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Auth error', err);
    res.status(401).json({ error: 'Invalid or expired ID token' });
  }
}

// --- Google OAuth2 for Calendar ---
const oauth2Client = new google.auth.OAuth2({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI, // e.g., http://localhost:4000/calendar/oauth2callback
});

function userTokensRef(uid) {
  return db.collection('userSecrets').doc(uid).collection('integrations').doc('google');
}

app.get('/health', (req, res) => res.json({ ok: true }));

// Return a consent URL the front-end can open in a popup
app.get('/calendar/authorize', requireAuth, (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/calendar.events'],
    include_granted_scopes: true,
    state: JSON.stringify({ uid: req.user.uid, returnTo: req.query.returnTo || '' }),
  });
  res.json({ url });
});

// OAuth callback Google redirects to
app.get('/calendar/oauth2callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const parsed = state ? JSON.parse(state) : {};
    const { tokens } = await oauth2Client.getToken(code);
    if (!parsed.uid) return res.status(400).send('Missing user context.');
    await userTokensRef(parsed.uid).set({ tokens }, { merge: true });
    const returnTo = parsed.returnTo || process.env.POST_OAUTH_REDIRECT || '/';
    // Notify opener (popup) if present and navigate
    res.send(
      '<script>window.opener && window.opener.postMessage({type:"google-connected"}, "*"); window.location = ' +
        JSON.stringify(returnTo) +
        ';</script>'
    );
  } catch (e) {
    console.error(e);
    res.status(500).send('OAuth error');
  }
});

async function calendarClientFor(uid) {
  const snap = await userTokensRef(uid).get();
  const data = snap.data();
  if (!data?.tokens?.refresh_token && !data?.tokens?.access_token) return null;

  oauth2Client.setCredentials(data.tokens);
  oauth2Client.on('tokens', async (tokens) => {
    if (tokens.refresh_token || tokens.access_token) {
      await userTokensRef(uid).set({ tokens: { ...data.tokens, ...tokens } }, { merge: true });
    }
  });

  return google.calendar({ version: 'v3', auth: oauth2Client });
}

// --- Tasks CRUD ---
app.get('/tasks', requireAuth, async (req, res) => {
  const col = db.collection('users').doc(req.user.uid).collection('tasks');
  const snapshot = await col.orderBy('createdAt', 'desc').get();
  const tasks = snapshot.docs.map((d) => ({ id: d.id, ...d.data() }));
  res.json({ tasks });
});

app.post('/tasks', requireAuth, async (req, res) => {
  const {
    title,
    description,
    dueDateTime,
    priority = 'medium',
    category = 'other',
    tags = [],
    reminder = 'none',
    calendarSync = false,
    timezone = 'Africa/Lagos', // West Africa Time
  } = req.body;

  if (!title) return res.status(400).json({ error: 'title is required' });

  const now = new Date();
  const ref = await db
    .collection('users')
    .doc(req.user.uid)
    .collection('tasks')
    .add({
      title,
      description: description || '',
      dueDateTime: dueDateTime || null, // ISO string
      priority,
      category,
      tags,
      reminder,
      calendarSync,
      timezone,
      completed: false,
      createdAt: now,
      updatedAt: now,
    });

  let calendarEventId = null;
  if (calendarSync && dueDateTime) {
    calendarEventId = await upsertCalendarEvent(req.user.uid, {
      id: ref.id,
      title,
      description,
      dueDateTime,
      timezone,
    });
    await ref.update({ calendarEventId, updatedAt: new Date() });
  }

  const created = await ref.get();
  res.status(201).json({ id: ref.id, ...created.data() });
});

app.patch('/tasks/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const payload = { ...req.body, updatedAt: new Date() };
  const ref = db
    .collection('users')
    .doc(req.user.uid)
    .collection('tasks')
    .doc(id);

  await ref.set(payload, { merge: true });

  if ((payload.calendarSync || payload.dueDateTime) && payload.calendarSync !== false) {
    const snap = await ref.get();
    const task = { id, ...snap.data() };
    if (task.dueDateTime) {
      const eventId = await upsertCalendarEvent(req.user.uid, task);
      await ref.update({ calendarEventId: eventId, updatedAt: new Date() });
    }
  }

  const updated = await ref.get();
  res.json({ id, ...updated.data() });
});

app.delete('/tasks/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const ref = db
    .collection('users')
    .doc(req.user.uid)
    .collection('tasks')
    .doc(id);

  const snap = await ref.get();
  const task = snap.data();

  if (task?.calendarEventId) {
    const cal = await calendarClientFor(req.user.uid);
    if (cal) {
      try {
        await cal.events.delete({ calendarId: 'primary', eventId: task.calendarEventId });
      } catch {}
    }
  }

  await ref.delete();
  res.json({ ok: true });
});

// --- Helper: create/update a Google Calendar event ---
async function upsertCalendarEvent(uid, task) {
  const cal = await calendarClientFor(uid);
  if (!cal) return null;

  const start = DateTime.fromISO(task.dueDateTime, { zone: task.timezone || 'Africa/Lagos' });
  const end = start.plus({ minutes: 30 });

  const event = {
    summary: task.title,
    description: task.description || '',
    start: { dateTime: start.toISO(), timeZone: start.zoneName },
    end: { dateTime: end.toISO(), timeZone: end.zoneName },
  };

  if (task.calendarEventId) {
    const resp = await cal.events.update({
      calendarId: 'primary',
      eventId: task.calendarEventId,
      requestBody: event,
    });
    return resp.data.id;
  } else {
    const resp = await cal.events.insert({ calendarId: 'primary', requestBody: event });
    return resp.data.id;
  }
}

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`TaskFlow API listening on :${port}`));