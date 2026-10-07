// ============================================================
// ইসলামী ছাত্র কল্যাণ সমিতি
// Backend API - Netlify Functions
// File: netlify/functions/api.mjs
// ============================================================

import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// ------------------------------------------------------------
// CONFIG
// ------------------------------------------------------------

const STORE_NAME = "samiti";
const SESSION_COOKIE = "samiti_session";
const SESSION_HOURS = 12;
const MAX_BODY = 100000;

const store = () =>
  getStore({
    name: STORE_NAME,
    consistency: "strong"
  });

// ------------------------------------------------------------
// BASIC HELPERS
// ------------------------------------------------------------

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function ok(data = {}) {
  return json({ ok: true, ...data });
}

function fail(message, status = 400) {
  return json({ ok: false, error: message }, status);
}

function clean(value, max = 5000) {
  if (value === undefined || value === null) return "";
  return String(value)
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, max);
}

function cleanNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function isValidDateString(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;

  const [y, m, d] = value.split("-").map(Number);
  const date = new Date(Date.UTC(y, m - 1, d));

  return (
    date.getUTCFullYear() === y &&
    date.getUTCMonth() === m - 1 &&
    date.getUTCDate() === d
  );
}

function todayBD() {
  const now = new Date();
  const bd = new Date(now.getTime() + 6 * 60 * 60 * 1000);
  return bd.toISOString().slice(0, 10);
}

function currentMonthBD() {
  return todayBD().slice(0, 7);
}

function monthCompare(a, b) {
  return a.localeCompare(b);
}

function addMonth(month) {
  const [y, m] = month.split("-").map(Number);

  const date = new Date(Date.UTC(y, m - 1, 1));
  date.setUTCMonth(date.getUTCMonth() + 1);

  return date.toISOString().slice(0, 7);
}

function monthsBetween(start, end) {
  const result = [];

  if (!/^\d{4}-\d{2}$/.test(start)) return result;
  if (!/^\d{4}-\d{2}$/.test(end)) return result;

  let cursor = start;

  while (cursor <= end && result.length < 240) {
    result.push(cursor);
    cursor = addMonth(cursor);
  }

  return result;
}

function validMobile(mobile) {
  return /^01\d{9}$/.test(mobile);
}

function validTxn(txn) {
  return /^[A-Za-z0-9._-]{4,80}$/.test(txn);
}

// ------------------------------------------------------------
// PASSWORD SECURITY
// ------------------------------------------------------------

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto.scryptSync(password, salt, 64, {
    N: 16384,
    r: 8,
    p: 1
  }).toString("hex");

  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  try {
    if (!stored || !stored.startsWith("scrypt$")) return false;

    const [, salt, savedHash] = stored.split("$");

    const calculated = crypto.scryptSync(password, salt, 64, {
      N: 16384,
      r: 8,
      p: 1
    });

    const saved = Buffer.from(savedHash, "hex");

    if (saved.length !== calculated.length) return false;

    return crypto.timingSafeEqual(saved, calculated);
  } catch {
    return false;
  }
}

// ------------------------------------------------------------
// SESSION
// ------------------------------------------------------------

function getSessionSecret() {
  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error(
      "SESSION_SECRET must be configured and at least 32 characters long."
    );
  }

  return secret;
}

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const signature = crypto
    .createHmac("sha256", getSessionSecret())
    .update(body)
    .digest("base64url");

  return `${body}.${signature}`;
}

function verifySession(token) {
  try {
    if (!token) return null;

    const [body, signature] = token.split(".");

    if (!body || !signature) return null;

    const expected = crypto
      .createHmac("sha256", getSessionSecret())
      .update(body)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length) return null;

    if (!crypto.timingSafeEqual(a, b)) return null;

    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    );

    if (!payload.exp || Date.now() > payload.exp) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function parseCookie(request, name) {
  const cookie = request.headers.get("cookie") || "";

  const parts = cookie.split(";");

  for (const part of parts) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function sessionCookie(token) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${SESSION_HOURS * 60 * 60}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=0"
  ].join("; ");
}

// ------------------------------------------------------------
// DATABASE
// ------------------------------------------------------------

function initialDB() {
  return {
    version: 2,

    members: [],

    payments: [],

    ledger: [],

    expenses: [],

    income: [],

    notices: [],

    notifs: [],

    audit: [],

    fails: {},

    seq: {
      member: 1,
      receipt: 0,
      ledger: 0,
      expense: 0,
      income: 0,
      notice: 0
    },

    settings: {
      name: "ইসলামী ছাত্র কল্যাণ সমিতি",
      currency: "BDT",
      monthly: 100,
      nagad: "",
      bkash: "",
      contact: "",
      address: "",
      instructions:
        "পেমেন্ট করার পর Transaction ID জমা দিন। Admin যাচাই করার পর টাকা হিসাবের মধ্যে যোগ হবে।",
      receiptPrefix: "ISK"
    }
  };
}

async function loadDB() {
  const s = store();

  let db = await s.get("db", {
    type: "json"
  });

  if (!db || typeof db !== "object") {
    db = initialDB();
    await s.setJSON("db", db);
  }

  migrateDB(db);

  return db;
}

async function saveDB(db) {
  await store().setJSON("db", db);
}

function migrateDB(db) {
  db.version ||= 2;

  db.members ||= [];
  db.payments ||= [];
  db.ledger ||= [];
  db.expenses ||= [];
  db.income ||= [];
  db.notices ||= [];
  db.notifs ||= [];
  db.audit ||= [];
  db.fails ||= {};

  db.seq ||= {};
  db.seq.member ||= 1;
  db.seq.receipt ||= 0;
  db.seq.ledger ||= 0;
  db.seq.expense ||= 0;
  db.seq.income ||= 0;
  db.seq.notice ||= 0;

  db.settings ||= initialDB().settings;

  for (const member of db.members) {
    member.active = member.active !== false;

    if (!Array.isArray(member.rateHistory)) {
      member.rateHistory = [
        {
          fromMonth: member.joinMonth || currentMonthBD(),
          amount: Number(member.monthly || db.settings.monthly || 100)
        }
      ];
    }
  }
}

// ------------------------------------------------------------
// RATE / CONTRIBUTION HISTORY
// ------------------------------------------------------------

function getMemberRate(member, month) {
  const history = Array.isArray(member.rateHistory)
    ? member.rateHistory
        .filter(
          x =>
            /^\d{4}-\d{2}$/.test(x.fromMonth) &&
            Number.isFinite(Number(x.amount))
        )
        .sort((a, b) => a.fromMonth.localeCompare(b.fromMonth))
    : [];

  let amount = Number(member.monthly || 100);

  for (const item of history) {
    if (item.fromMonth <= month) {
      amount = Number(item.amount);
    }
  }

  return amount;
}

function setMemberRate(member, fromMonth, amount) {
  if (!Array.isArray(member.rateHistory)) {
    member.rateHistory = [];
  }

  member.rateHistory = member.rateHistory.filter(
    x => x.fromMonth !== fromMonth
  );

  member.rateHistory.push({
    fromMonth,
    amount
  });

  member.rateHistory.sort((a, b) =>
    a.fromMonth.localeCompare(b.fromMonth)
  );

  member.monthly = amount;
}

// ------------------------------------------------------------
// ID GENERATORS
// ------------------------------------------------------------

function nextMemberId(db) {
  db.seq.member = Number(db.seq.member || 1) + 1;

  return `ISK-${String(db.seq.member).padStart(4, "0")}`;
}

function nextLedgerId(db) {
  db.seq.ledger = Number(db.seq.ledger || 0) + 1;

  return `LED-${String(db.seq.ledger).padStart(8, "0")}`;
}

function nextReceiptId(db) {
  db.seq.receipt = Number(db.seq.receipt || 0) + 1;

  const prefix = clean(db.settings.receiptPrefix || "ISK", 20)
    .replace(/\s+/g, "")
    .toUpperCase();

  return `${prefix}-R-${String(db.seq.receipt).padStart(6, "0")}`;
}

function nextExpenseId(db) {
  db.seq.expense = Number(db.seq.expense || 0) + 1;

  return `EXP-${String(db.seq.expense).padStart(6, "0")}`;
}

function nextIncomeId(db) {
  db.seq.income = Number(db.seq.income || 0) + 1;

  return `INC-${String(db.seq.income).padStart(6, "0")}`;
}

function nextNoticeId(db) {
  db.seq.notice = Number(db.seq.notice || 0) + 1;

  return `NOTICE-${String(db.seq.notice).padStart(6, "0")}`;
}

// ------------------------------------------------------------
// AUDIT / NOTIFICATION
// ------------------------------------------------------------

function audit(db, actor, action, details = {}) {
  db.audit.unshift({
    id: crypto.randomUUID(),
    actor: actor?.id || "SYSTEM",
    actorRole: actor?.role || "SYSTEM",
    action,
    details,
    createdAt: new Date().toISOString()
  });

  db.audit = db.audit.slice(0, 2000);
}

function notify(db, memberId, title, message) {
  db.notifs.unshift({
    id: crypto.randomUUID(),
    memberId,
    title: clean(title, 200),
    message: clean(message, 1000),
    read: false,
    createdAt: new Date().toISOString()
  });

  db.notifs = db.notifs.slice(0, 5000);
}

// ------------------------------------------------------------
// USER HELPERS
// ------------------------------------------------------------

function publicUser(user) {
  if (!user) return null;

  const copy = { ...user };

  delete copy.passwordHash;
  delete copy.rateHistory;

  return copy;
}

function roleRank(role) {
  if (role === "super_admin") return 3;
  if (role === "admin") return 2;
  if (role === "member") return 1;
  return 0;
}

function requireRole(user, role) {
  return roleRank(user?.role) >= roleRank(role);
}

// ------------------------------------------------------------
// BALANCE
// ------------------------------------------------------------

function memberBalance(db, memberId) {
  return db.ledger
    .filter(x => x.memberId === memberId)
    .reduce((sum, x) => sum + Number(x.amount || 0), 0);
}

function committeeFund(db) {
  const approvedPayments = db.payments
    .filter(x => x.status === "approved")
    .reduce((sum, x) => sum + Number(x.amount || 0), 0);

  const income = db.income.reduce(
    (sum, x) => sum + Number(x.amount || 0),
    0
  );

  const expenses = db.expenses.reduce(
    (sum, x) => sum + Number(x.amount || 0),
    0
  );

  return approvedPayments + income - expenses;
}

// ------------------------------------------------------------
// MEMBER SUMMARY
// ------------------------------------------------------------

function memberSummary(db, member) {
  const currentMonth = currentMonthBD();
  const joinMonth = member.joinMonth || currentMonth;

  const months = monthsBetween(joinMonth, currentMonth);

  const approvedMonths = new Set(
    db.payments
      .filter(
        p => p.memberId === member.id && p.status === "approved"
      )
      .map(p => p.month)
  );

  const pendingMonths = new Set(
    db.payments
      .filter(
        p => p.memberId === member.id && p.status === "pending"
      )
      .map(p => p.month)
  );

  const dueMonths = months.filter(
    m => !approvedMonths.has(m) && !pendingMonths.has(m)
  );

  const dueTotal = dueMonths.reduce(
    (sum, month) => sum + getMemberRate(member, month),
    0
  );

  const pendingTotal = months
    .filter(m => pendingMonths.has(m))
    .reduce((sum, month) => sum + getMemberRate(member, month), 0);

  const currentStatus = approvedMonths.has(currentMonth)
    ? "paid"
    : pendingMonths.has(currentMonth)
      ? "pending"
      : "due";

  const lastPayment = db.payments
    .filter(p => p.memberId === member.id)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];

  return {
    balance: memberBalance(db, member.id),
    dueMonths,
    dueTotal,
    pendingTotal,
    approvedMonths: [...approvedMonths].sort(),
    pendingMonths: [...pendingMonths].sort(),
    currentMonth,
    currentStatus,
    lastPayment: lastPayment || null
  };
}

// ------------------------------------------------------------
// ADMIN STATS
// ------------------------------------------------------------

function adminStats(db) {
  const activeMembers = db.members.filter(
    x => x.active !== false && x.role === "member"
  );

  const month = currentMonthBD();

  const currentApproved = new Set(
    db.payments
      .filter(
        p =>
          p.month === month &&
          p.status === "approved"
      )
      .map(p => p.memberId)
  );

  const currentPending = new Set(
    db.payments
      .filter(
        p =>
          p.month === month &&
          p.status === "pending"
      )
      .map(p => p.memberId)
  );

  const approvedAmount = db.payments
    .filter(p => p.status === "approved")
    .reduce((s, p) => s + Number(p.amount || 0), 0);

  const pendingAmount = db.payments
    .filter(p => p.status === "pending")
    .reduce((s, p) => s + Number(p.amount || 0), 0);

  const expenseAmount = db.expenses.reduce(
    (s, x) => s + Number(x.amount || 0),
    0
  );

  const incomeAmount = db.income.reduce(
    (s, x) => s + Number(x.amount || 0),
    0
  );

  const dueMembers = activeMembers.filter(
    m =>
      !currentApproved.has(m.id) &&
      !currentPending.has(m.id)
  ).length;

  return {
    totalMembers: activeMembers.length,
    currentPaidMembers: currentApproved.size,
    currentPendingMembers: currentPending.size,
    currentDueMembers: dueMembers,
    approvedAmount,
    pendingAmount,
    expenseAmount,
    incomeAmount,
    fund: committeeFund(db),
    totalPayments: db.payments.length
  };
}

// ------------------------------------------------------------
// AUTHENTICATION
// ------------------------------------------------------------

async function getCurrentUser(request, db) {
  const token = parseCookie(request, SESSION_COOKIE);

  const session = verifySession(token);

  if (!session?.id) return null;

  const user = db.members.find(x => x.id === session.id);

  if (!user || user.active === false) return null;

  return user;
}

function loginRateLimited(db, key) {
  const record = db.fails[key];

  if (!record) return false;

  if (Date.now() > record
