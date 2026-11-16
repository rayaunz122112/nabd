/* نبض الطوارئ: خادم Node لمنصة Render مع قاعدة بيانات Postgres.
   كل طلب يمر بالتحقق من الجلسة، ثم رمز الحماية من الطلبات المزوّرة، ثم الدور، ثم المناوبة، ثم صحة المدخلات.
   سجل التدقيق للإضافة فقط على مستوى قاعدة البيانات. */
"use strict";
const http = require("node:http"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 10000);
const TZ_MIN = Number(process.env.TZ_OFFSET_MINUTES || 180);          // توقيت السعودية: +3 ساعات
const IDLE_MS = Number(process.env.IDLE_MINUTES || 20) * 60000;
const LIMIT_MIN = 240;
const REASONS = ["انتظار سرير تنويم", "انتظار نتائج المختبر", "انتظار الأشعة", "انتظار استشارة تخصصية", "ازدحام القسم أو نقص الكوادر", "انتظار نقل أو إسعاف", "سبب يخص المريض أو ذويه", "انتظار قرار الطبيب المعالج", "أخرى"];
const ROLES = {admin: "مدير النظام / مشرف القسم", supervisor: "مشرف مناوبة", viewer: "مستخدم اطلاع"};
const PERMS = {
  "dashboard.view": ["admin", "supervisor", "viewer"], "delays.view": ["admin", "supervisor", "viewer"],
  "visits.view": ["admin", "supervisor"], "visit.write": ["admin", "supervisor"],
  "duty.take": ["supervisor"], "handover.view": ["admin", "supervisor"], "users.manage": ["admin"], "audit.view": ["admin"]};

if (!process.env.DATABASE_URL){ console.error("DATABASE_URL is not set. Link a Render Postgres database to this service."); process.exit(1); }
const pool = new Pool({connectionString: process.env.DATABASE_URL, max: 5, ssl: process.env.PGSSLMODE === "require" ? {rejectUnauthorized: false} : undefined});
const q = async (text, params = []) => (await pool.query(text, params)).rows;
const one = async (text, params) => (await q(text, params))[0] || null;
const N = v => v === null || v === undefined ? null : Number(v);

class ApiError extends Error { constructor(code, message){ super(message); this.code = code; } }
const fail = (code, message) => { throw new ApiError(code, message); };
const now = () => Date.now();
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const marks = (arr, from = 1) => arr.map((_, i) => "$" + (i + from)).join(",");

/* ---------- قاعدة البيانات ---------- */
async function migrate(){
  const ddl = [
    `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, name TEXT NOT NULL, role TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT false, pending BOOLEAN NOT NULL DEFAULT false, pass TEXT NOT NULL, failed INTEGER NOT NULL DEFAULT 0, locked_until BIGINT NOT NULL DEFAULT 0, last_login BIGINT, created_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS shifts (id SERIAL PRIMARY KEY, op_date TEXT NOT NULL, type INTEGER NOT NULL, supervisor_id INTEGER NOT NULL, opened_at BIGINT NOT NULL, closed_at BIGINT, visits INTEGER, doctors TEXT NOT NULL DEFAULT '[]')`,
    `CREATE TABLE IF NOT EXISTS visits (id SERIAL PRIMARY KEY, code TEXT NOT NULL, arrived_at BIGINT NOT NULL, op_date TEXT NOT NULL, shift_type INTEGER NOT NULL, exit_at BIGINT, reason INTEGER NOT NULL, note TEXT NOT NULL DEFAULT '', doctor TEXT, by_id INTEGER NOT NULL, created_at BIGINT NOT NULL)`,
    `ALTER TABLE visits ADD COLUMN IF NOT EXISTS mrn TEXT`,
    `ALTER TABLE visits ADD COLUMN IF NOT EXISTS voided_at BIGINT`,
    `ALTER TABLE visits ADD COLUMN IF NOT EXISTS voided_by INTEGER`,
    `CREATE INDEX IF NOT EXISTS visits_date ON visits (op_date)`,
    `CREATE TABLE IF NOT EXISTS handovers (id SERIAL PRIMARY KEY, from_user INTEGER, to_user INTEGER NOT NULL, at BIGINT NOT NULL, over_count INTEGER NOT NULL DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS audit (seq SERIAL PRIMARY KEY, at BIGINT NOT NULL, user_id INTEGER, username TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT, summary TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER, csrf TEXT NOT NULL, last BIGINT NOT NULL, created BIGINT NOT NULL)`,
    `CREATE OR REPLACE FUNCTION nabd_audit_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit log is append-only'; END; $$ LANGUAGE plpgsql`,
    `DROP TRIGGER IF EXISTS audit_no_change ON audit`,
    `CREATE TRIGGER audit_no_change BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION nabd_audit_immutable()`,
    `DROP TRIGGER IF EXISTS audit_no_truncate ON audit`,
    `CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit FOR EACH STATEMENT EXECUTE FUNCTION nabd_audit_immutable()`];
  for (const s of ddl) await q(s);
  await q(`DELETE FROM sessions WHERE last < $1`, [now() - 7 * 86400000]);
}

const auditHash = (prev, e) => sha(prev + JSON.stringify([e.at, e.userId, e.action, e.entity, e.entityId, e.summary]));
async function audit(u, action, entity, entityId, summary){
  const last = await one(`SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`), prev = last ? last.hash : "0";
  const e = {at: now(), userId: u ? Number(u.id) : null, action, entity, entityId: entityId === null || entityId === undefined ? null : String(entityId), summary};
  await q(`INSERT INTO audit (at, user_id, username, name, role, action, entity, entity_id, summary, prev, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [e.at, e.userId, u ? u.username : "—", u ? u.name : "—", u ? u.role : "—", action, entity, e.entityId, summary, prev, auditHash(prev, e)]);
}
async function deny(u, what){ await audit(u, "denied", "api", what, "طلب مرفوض: " + what); fail("forbidden", "ليست لديك صلاحية لتنفيذ هذا الإجراء."); }

/* ---------- المدخلات وكلمات المرور ---------- */
function pInt(p, k, min, max, label){ let v = p[k]; if (typeof v === "string") v = v.trim(); if (v === null || v === undefined || v === "" || typeof v === "boolean" || !Number.isInteger(Number(v)) || Number(v) < min || Number(v) > max) fail("invalid", `${label}: أدخل عدداً صحيحاً بين ${min} و${max}.`); return Number(v); }
function pStr(p, k, min, max, label){ let v = p[k]; v = (typeof v === "string" || typeof v === "number") ? String(v).trim() : ""; const n = [...v].length; if (n < min) fail("invalid", `${label}: حقل مطلوب.`); if (n > max) fail("invalid", `${label}: الحد الأقصى ${max} حرفاً.`); return v; }
function checkUsername(x){ if (!/^[a-z0-9._-]{3,20}$/.test(x)) fail("invalid", "اسم المستخدم: 3 إلى 20 من الأحرف الإنجليزية الصغيرة والأرقام والنقطة والشرطة."); }
function checkPassword(p){ const a = typeof p.password === "string" ? p.password : ""; if (a.length < 8 || a.length > 200 || !/\d/.test(a) || !/\D/.test(a)) fail("invalid", "كلمة المرور: 8 خانات على الأقل، وفيها حرف ورقم."); if (a !== p.password2) fail("invalid", "كلمتا المرور غير متطابقتين."); return a; }
function hashPassword(pass){ const salt = crypto.randomBytes(16); return "s1$" + salt.toString("hex") + "$" + crypto.scryptSync(pass, salt, 64).toString("hex"); }
function verifyPassword(pass, stored){ const [v, saltHex, keyHex] = String(stored || "").split("$"); const salt = v === "s1" && saltHex ? Buffer.from(saltHex, "hex") : Buffer.alloc(16); const key = crypto.scryptSync(String(pass), salt, 64), ref = v === "s1" && keyHex ? Buffer.from(keyHex, "hex") : Buffer.alloc(64); return v === "s1" && ref.length === 64 && crypto.timingSafeEqual(key, ref); }

/* ---------- الوقت والمناوبات ---------- */
const shiftOfHour = h => h >= 7 && h < 15 ? 0 : h >= 15 && h < 23 ? 1 : 2;
const isoDay = d => d.toISOString().slice(0, 10);
function slotOf(ms){ const d = new Date(ms + TZ_MIN * 60000), h = d.getUTCHours(); return {date: isoDay(h < 7 ? new Date(d.getTime() - 86400000) : d), type: shiftOfHour(h)}; }
function lastDates(n){ const t = Date.parse(slotOf(now()).date + "T00:00:00Z"), o = []; for (let i = n - 1; i >= 0; i--) o.push(isoDay(new Date(t - i * 86400000))); return o; }
const pub = u => ({id: Number(u.id), username: u.username, name: u.name, role: u.role});
const openShift = () => one(`SELECT * FROM shifts WHERE closed_at IS NULL ORDER BY id DESC LIMIT 1`);
const shiftDoctors = s => { if (!s) return []; try { const d = JSON.parse(s.doctors); return Array.isArray(d) ? d : []; } catch(e){ return []; } };
async function canDuty(u){ if (u.role === "admin") return true; const c = await openShift(); return !!c && Number(c.supervisor_id) === Number(u.id); }
async function duty(u){ if (!(await canDuty(u))) await deny(u, "التسجيل خارج مناوبته الجارية"); }
const vMins = v => Math.floor(((N(v.exit_at) || now()) - N(v.arrived_at)) / 60000);
async function names(){ const m = new Map(); for (const r of await q(`SELECT id, name FROM users`)) m.set(Number(r.id), r.name); return id => id === null || id === undefined ? "—" : (m.get(Number(id)) || "—"); }
const vView = (v, nm) => ({id: Number(v.id), code: v.code, arrivedAt: N(v.arrived_at), exitAt: N(v.exit_at), mins: vMins(v), reason: Number(v.reason), note: v.note || "", doctor: v.doctor || null, mrn: v.mrn || null, by: nm(v.by_id), shiftType: Number(v.shift_type)});
async function getVisit(p){ const v = await one(`SELECT * FROM visits WHERE voided_at IS NULL AND id = $1`, [pInt(p, "id", 1, 2147483647, "رقم الحالة")]); if (!v) fail("notfound", "الحالة غير موجودة."); return v; }
const pctOf = (vis, late) => vis > 0 ? Math.max(0, Math.round((vis - late) / vis * 100)) : null;
const visitsIn = dates => q(`SELECT * FROM visits WHERE voided_at IS NULL AND op_date IN (${marks(dates)})`, dates);
async function coverage(dates, L, type){
  const rows = await q(`SELECT op_date, type, COALESCE(SUM(visits), 0)::int AS v, SUM(CASE WHEN visits > 0 THEN 0 ELSE 1 END)::int AS m FROM shifts WHERE op_date IN (${marks(dates)})${type === undefined ? "" : " AND type = " + Number(type)} GROUP BY op_date, type`, dates);
  const tot = {}, key = (d, t) => type === undefined ? d : d + "|" + t; let missing = 0;
  for (const r of rows){ missing += Number(r.m); if (Number(r.v) > 0) tot[key(r.op_date, r.type)] = (tot[key(r.op_date, r.type)] || 0) + Number(r.v); }
  const vis = Object.values(tot).reduce((a, b) => a + b, 0), late = L.filter(v => tot[key(v.op_date, v.shift_type)]).length;
  return {vis, pct: pctOf(vis, late), partial: vis > 0 && (late < L.length || missing > 0)};
}
async function jStats(){ const today = slotOf(now()).date, L = await visitsIn([today]), c = await coverage([today], L), o = await one(`SELECT COUNT(*)::int AS n FROM visits WHERE voided_at IS NULL AND exit_at IS NULL`); return {over: o.n, lateToday: L.length, visitsToday: c.vis, pct: c.pct}; }
function setReason(p){ if (p.reason === undefined || p.reason === null || p.reason === "") fail("invalid", "اختر سبب التأخير."); const r = pInt(p, "reason", 0, REASONS.length - 1, "سبب التأخير"), note = pStr(p, "note", 0, 300, "التوضيح"); if (r === REASONS.length - 1 && [...note].length < 3) fail("invalid", "اكتب سبب التأخير في الخانة أولاً."); return [r, note]; }
async function pickDoctor(p, current){ if (!("doctor" in p)) return current; const d = typeof p.doctor === "string" ? p.doctor.trim() : ""; if (d && d !== current && !shiftDoctors(await openShift()).includes(d)) fail("invalid", "الطبيب غير موجود في قائمة أطباء المناوبة."); return d || null; }
function pickMrn(p, current){ if (!("mrn" in p)) return current; const m = (typeof p.mrn === "string" || typeof p.mrn === "number") ? String(p.mrn).trim() : ""; if (m && !/^[A-Za-z0-9-]{1,20}$/.test(m)) fail("invalid", "رقم الملف: أرقام وأحرف إنجليزية وشرطة فقط، حتى 20 خانة."); return m || null; }
async function delaysReport(u, p){
  const week = p.period === "week", dates = lastDates(week ? 7 : 1), L = await visitsIn(dates), cv = await coverage(dates, L), done = L.filter(v => v.exit_at !== null), nm = await names();
  const byReason = REASONS.map((n, i) => ({name: n, count: L.filter(v => Number(v.reason) === i).length})).filter(x => x.count).sort((a, b) => b.count - a.count);
  let byDoctor = null; if (u.role !== "viewer"){ const m = {}; for (const v of L){ const k = v.doctor || "غير محدد"; m[k] = (m[k] || 0) + 1; } byDoctor = Object.entries(m).map(([name, count]) => ({name, count})).sort((a, b) => b.count - a.count); }
  const byShift = []; for (let t = 0; t < 3; t++){ const Lt = L.filter(v => Number(v.shift_type) === t), c = await coverage(dates, Lt, t); byShift.push({type: t, visits: c.vis, late: Lt.length, pct: c.pct}); }
  return {period: week ? "week" : "today", from: dates[0], to: dates[dates.length - 1], visits: cv.vis, late: L.length, pct: cv.pct, partial: cv.partial, inside: L.length - done.length,
    avg: done.length ? Math.round(done.reduce((a, v) => a + vMins(v), 0) / done.length) : 0, byReason, byDoctor, byShift,
    rows: u.role === "viewer" ? null : [...L].sort((a, b) => N(b.arrived_at) - N(a.arrived_at)).slice(0, 300).map(v => vView(v, nm))};
}

/* ---------- الإجراءات: لكل إجراء صلاحية يتحقق منها الخادم قبل التنفيذ ---------- */
const H = {
  "dashboard.get": ["dashboard.view", async (u) => {
    const cur = await openShift(), wk = await delaysReport(u, {period: "week"}), td = await delaysReport(u, {period: "today"}), nm = await names(), trend = [];
    for (const d of lastDates(7)){ const Ld = await visitsIn([d]), c = await coverage([d], Ld); trend.push({date: d, visits: c.vis, late: Ld.length, pct: c.pct}); }
    const docs = shiftDoctors(cur), pend = u.role === "admin" ? (await one(`SELECT COUNT(*)::int AS n FROM users WHERE pending`)).n : 0;
    return {duty: cur ? {holder: nm(cur.supervisor_id), since: N(cur.opened_at), doctors: u.role === "viewer" ? null : docs, doctorCount: docs.length} : null, journey: await jStats(),
      week: {visits: wk.visits, late: wk.late, pct: wk.pct, avg: wk.avg}, trend, byShift: td.byShift, reasons: wk.byReason.slice(0, 6), pendingUsers: pend};
  }],
  "handovers.list": ["handover.view", async () => { const nm = await names(); return (await q(`SELECT * FROM handovers ORDER BY id DESC LIMIT 30`)).map(h => ({id: Number(h.id), from: h.from_user === null ? "—" : nm(h.from_user), to: nm(h.to_user), at: N(h.at), over: Number(h.over_count)})); }],
  "duty.get": ["dashboard.view", async (u) => { const cur = await openShift(), st = await jStats(), nm = await names(), mine = !!cur && Number(cur.supervisor_id) === Number(u.id);
    return {holder: cur ? nm(cur.supervisor_id) : null, since: cur ? N(cur.opened_at) : null, isMe: mine, canTake: u.role === "supervisor" && !mine, over: st.over, visits: cur && cur.visits !== null ? Number(cur.visits) : 0}; }],
  "duty.take": ["duty.take", async (u) => {
    const cur = await openShift(), t = now(), over = (await jStats()).over, nm = await names();
    if (cur && Number(cur.supervisor_id) === Number(u.id)) fail("conflict", "أنت المشرف المناوب حالياً.");
    if (cur) await q(`UPDATE shifts SET closed_at = $1 WHERE id = $2`, [t, cur.id]);
    const sl = slotOf(t); await q(`INSERT INTO shifts (op_date, type, supervisor_id, opened_at) VALUES ($1,$2,$3,$4)`, [sl.date, sl.type, u.id, t]);
    const h = await one(`INSERT INTO handovers (from_user, to_user, at, over_count) VALUES ($1,$2,$3,$4) RETURNING id`, [cur ? cur.supervisor_id : null, u.id, t, over]);
    await audit(u, "duty.take", "handover", h.id, `استلام المناوبة من ${cur ? nm(cur.supervisor_id) : "—"}: ${over} حالة متجاوزة ما زالت داخل القسم`); return {ok: true};
  }],
  "users.list": ["users.manage", async () => { const t = now(); return (await q(`SELECT * FROM users ORDER BY pending DESC, id ASC`)).map(x => ({...pub(x), active: !!x.active, pending: !!x.pending, locked: N(x.locked_until) > t, lastLogin: N(x.last_login)})); }],
  "user.create": ["users.manage", async (u, p) => {
    const username = pStr(p, "username", 3, 20, "اسم المستخدم").toLowerCase(); checkUsername(username);
    if (await one(`SELECT 1 AS x FROM users WHERE username = $1`, [username])) fail("conflict", "اسم المستخدم مستخدم من قبل.");
    if (!ROLES[p.role]) fail("invalid", "اختر دوراً صالحاً."); const name = pStr(p, "name", 2, 40, "الاسم"), temp = "T-" + crypto.randomBytes(5).toString("hex");
    const r = await one(`INSERT INTO users (username, name, role, active, pending, pass, created_at) VALUES ($1,$2,$3,true,false,$4,$5) RETURNING id`, [username, name, p.role, hashPassword(temp), now()]);
    await audit(u, "user.create", "user", r.id, `${username} بدور ${ROLES[p.role]}`); return {username, tempPassword: temp};
  }],
  "user.update": ["users.manage", async (u, p) => {
    const t = await one(`SELECT * FROM users WHERE id = $1`, [pInt(p, "id", 1, 2147483647, "المستخدم")]); if (!t) fail("notfound", "المستخدم غير موجود."); const ch = [], self = Number(t.id) === Number(u.id);
    if ("role" in p && p.role !== t.role){ if (!ROLES[p.role]) fail("invalid", "دور غير صالح."); if (self) fail("conflict", "لا يمكنك تغيير دورك بنفسك."); await q(`UPDATE users SET role = $1 WHERE id = $2`, [p.role, t.id]); ch.push(`الدور: ${ROLES[t.role]} ← ${ROLES[p.role]}`); }
    if ("active" in p && !!p.active !== !!t.active){ if (self) fail("conflict", "لا يمكنك إيقاف حسابك بنفسك."); const a = !!p.active;
      await q(`UPDATE users SET active = $1, pending = false WHERE id = $2`, [a, t.id]); if (!a) await q(`UPDATE sessions SET user_id = NULL WHERE user_id = $1`, [t.id]); ch.push(a ? (t.pending ? "اعتماد الحساب" : "تفعيل الحساب") : "إيقاف الحساب"); }
    if (p.unlock){ await q(`UPDATE users SET failed = 0, locked_until = 0 WHERE id = $1`, [t.id]); ch.push("فك القفل"); }
    if (ch.length) await audit(u, "user.update", "user", t.id, `${t.username}: ${ch.join("، ")}`); return {ok: true};
  }],
  "audit.list": ["audit.view", async () => (await q(`SELECT * FROM audit ORDER BY seq DESC LIMIT 400`)).map(e => ({seq: Number(e.seq), at: N(e.at), userId: N(e.user_id), username: e.username, name: e.name, role: e.role, action: e.action, entity: e.entity, entityId: e.entity_id, summary: e.summary}))],
  "audit.verify": ["audit.view", async () => { let prev = "0", n = 0; const rows = await q(`SELECT * FROM audit ORDER BY seq ASC`);
    for (const e of rows){ n++; if (e.prev !== prev || e.hash !== auditHash(prev, {at: N(e.at), userId: N(e.user_id), action: e.action, entity: e.entity, entityId: e.entity_id, summary: e.summary})) return {ok: false, at: Number(e.seq), count: rows.length}; prev = e.hash; }
    return {ok: true, count: n}; }],
  "visits.list": ["visits.view", async (u, p) => { const cur = await openShift(), nm = await names();
    const L = p.filter === "today" ? await q(`SELECT * FROM visits WHERE voided_at IS NULL AND op_date = $1 ORDER BY arrived_at ASC`, [slotOf(now()).date]) : await q(`SELECT * FROM visits WHERE voided_at IS NULL AND exit_at IS NULL ORDER BY arrived_at ASC`);
    return {rows: L.map(v => vView(v, nm)), stats: await jStats(), canWrite: await canDuty(u), shiftVisits: cur && Number(cur.visits) > 0 ? Number(cur.visits) : null, doctors: shiftDoctors(cur)}; }],
  "visit.get": ["visits.view", async (u, p) => ({...vView(await getVisit(p), await names()), canWrite: await canDuty(u), doctors: shiftDoctors(await openShift())})],
  "visit.create": ["visit.write", async (u, p) => {
    await duty(u); const m = /^(\d{1,2}):(\d{2})$/.exec(String(p.arr || "")); if (!m || +m[1] > 23 || +m[2] > 59) fail("invalid", "وقت الدخول: أدخل وقتاً صحيحاً.");
    const t = now(), d = new Date(t + TZ_MIN * 60000); let at = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), +m[1], +m[2]) - TZ_MIN * 60000; if (at > t) at -= 86400000;
    if (t - at < LIMIT_MIN * 60000) fail("invalid", "لم يمضِ على هذا الدخول 4 ساعات بعد. تُسجَّل الحالة عند تجاوزها.");
    const [reason, note] = setReason(p), doctor = await pickDoctor(p, null), mrn = pickMrn(p, null), sl = slotOf(at);
    const r = await one(`INSERT INTO visits (code, arrived_at, op_date, shift_type, reason, note, doctor, by_id, created_at, mrn) VALUES ('', $1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, [at, sl.date, sl.type, reason, note, doctor, u.id, t, mrn]);
    const code = "ز-" + String(r.id).padStart(4, "0"); await q(`UPDATE visits SET code = $1 WHERE id = $2`, [code, r.id]);
    await audit(u, "visit.create", "visit", r.id, `تسجيل حالة متجاوزة ${code}: ${REASONS[reason]}${doctor ? "، الطبيب المعالج: " + doctor : ""}`); return {id: Number(r.id), code};
  }],
  "visit.exit": ["visit.write", async (u, p) => { await duty(u); const v = await getVisit(p); if (v.exit_at !== null) fail("conflict", "سُجّل خروج هذه الحالة من قبل."); const t = now();
    await q(`UPDATE visits SET exit_at = $1 WHERE id = $2`, [t, v.id]); await audit(u, "visit.exit", "visit", v.id, `${v.code}: خرج من القسم بعد ${Math.floor((t - N(v.arrived_at)) / 60000)} دقيقة`); return {ok: true}; }],
  "visit.reason": ["visit.write", async (u, p) => { await duty(u); const v = await getVisit(p), [reason, note] = setReason(p), doctor = await pickDoctor(p, v.doctor || null), mrn = pickMrn(p, v.mrn || null);
    await q(`UPDATE visits SET reason = $1, note = $2, doctor = $3, mrn = $4 WHERE id = $5`, [reason, note, doctor, mrn, v.id]); await audit(u, "visit.reason", "visit", v.id, `${v.code}: ${REASONS[reason]}${doctor ? "، الطبيب المعالج: " + doctor : ""}`); return {ok: true}; }],
  "visit.void": ["visit.write", async (u, p) => { await duty(u); const v = await getVisit(p); await q(`UPDATE visits SET voided_at = $1, voided_by = $2 WHERE id = $3`, [now(), u.id, v.id]); await audit(u, "visit.void", "visit", v.id, `إلغاء الحالة ${v.code} لأنها سُجّلت بالخطأ`); return {ok: true}; }],
  "doctor.add": ["visit.write", async (u, p) => { await duty(u); const cur = await openShift(); if (!cur) fail("conflict", "لا توجد مناوبة جارية. يستلم مشرف المناوبة أولاً."); const docs = shiftDoctors(cur), name = pStr(p, "name", 2, 40, "اسم الطبيب");
    if (docs.length >= 15) fail("invalid", "الحد الأقصى 15 طبيباً في المناوبة."); if (docs.includes(name)) fail("conflict", "الاسم مضاف من قبل.");
    docs.push(name); await q(`UPDATE shifts SET doctors = $1 WHERE id = $2`, [JSON.stringify(docs), cur.id]); await audit(u, "doctor.add", "shift", cur.id, "إضافة طبيب للمناوبة: " + name); return {ok: true}; }],
  "doctor.remove": ["visit.write", async (u, p) => { await duty(u); const cur = await openShift(), docs = shiftDoctors(cur), name = String(p.name || ""), i = docs.indexOf(name); if (i < 0) fail("notfound", "الاسم غير موجود في المناوبة.");
    docs.splice(i, 1); await q(`UPDATE shifts SET doctors = $1 WHERE id = $2`, [JSON.stringify(docs), cur.id]); await audit(u, "doctor.remove", "shift", cur.id, "إزالة طبيب من المناوبة: " + name); return {ok: true}; }],
  "shift.total": ["visit.write", async (u, p) => { await duty(u); const cur = await openShift(); if (!cur) fail("conflict", "لا توجد مناوبة جارية."); const raw = String(p.visits === undefined || p.visits === null ? "" : p.visits).trim(), v = raw === "" ? null : pInt(p, "visits", 0, 999, "إجمالي الزيارات");
    await q(`UPDATE shifts SET visits = $1 WHERE id = $2`, [v, cur.id]); await audit(u, "shift.total", "shift", cur.id, v === null ? "أُزيل إجمالي زيارات المناوبة" : `إجمالي زيارات المناوبة: ${v}`); return {ok: true}; }],
  "delays.report": ["delays.view", delaysReport]
};

/* ---------- الجلسات ---------- */
const cookieOf = req => { const m = /(?:^|;\s*)nabd_sid=([a-f0-9]{48})/.exec(req.headers.cookie || ""); return m ? m[1] : null; };
const isHttps = req => (req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
function setCookie(res, req, token){ res.setHeader("Set-Cookie", `nabd_sid=${token}; Path=/; HttpOnly; SameSite=Strict${isHttps(req) ? "; Secure" : ""}`); }
async function newSession(res, req, userId){ const token = crypto.randomBytes(24).toString("hex"), s = {id: sha(token), user_id: userId, csrf: crypto.randomBytes(24).toString("hex"), last: now()}; await q(`INSERT INTO sessions (id, user_id, csrf, last, created) VALUES ($1,$2,$3,$4,$4)`, [s.id, userId, s.csrf, s.last]); setCookie(res, req, token); return s; }
async function loadSession(req, res){ const token = cookieOf(req); let s = token ? await one(`SELECT * FROM sessions WHERE id = $1`, [sha(token)]) : null; if (!s) s = await newSession(res, req, null); return s; }
async function currentUser(s){
  if (s.user_id === null || s.user_id === undefined) return null;
  if (now() - N(s.last) > IDLE_MS){ await q(`UPDATE sessions SET user_id = NULL WHERE id = $1`, [s.id]); s.user_id = null; return null; }
  const u = await one(`SELECT * FROM users WHERE id = $1`, [s.user_id]); if (!u || !u.active){ await q(`UPDATE sessions SET user_id = NULL WHERE id = $1`, [s.id]); s.user_id = null; return null; }
  await q(`UPDATE sessions SET last = $1 WHERE id = $2`, [now(), s.id]); return u;
}

/* ---------- معالجة الطلب ---------- */
async function handle(req, res, action, p){
  let s = await loadSession(req, res);
  const usersCount = async () => (await one(`SELECT COUNT(*)::int AS n FROM users`)).n;
  try {
    let data;
    if (action === "auth.me"){ const u = await currentUser(s); data = {setup: (await usersCount()) === 0, user: u ? pub(u) : null}; }
    else {
      const sent = String(req.headers["x-csrf"] || ""); if (sent.length !== s.csrf.length || !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(s.csrf))) fail("csrf", "انتهت صلاحية الصفحة. أعد تحميلها ثم حاول مرة أخرى.");
      if (action === "auth.setup"){
        if ((await usersCount()) > 0) fail("forbidden", "أُنجز الإعداد من قبل.");
        const name = pStr(p, "name", 2, 40, "الاسم"), username = pStr(p, "username", 3, 20, "اسم المستخدم").toLowerCase(); checkUsername(username); const pass = checkPassword(p);
        const r = await one(`INSERT INTO users (username, name, role, active, pending, pass, created_at) VALUES ($1,$2,'admin',true,false,$3,$4) RETURNING *`, [username, name, hashPassword(pass), now()]);
        await audit(r, "user.create", "user", r.id, "إعداد أول مرة: إنشاء حساب مدير النظام"); data = {ok: true};
      } else if (action === "auth.signup"){
        if ((await usersCount()) === 0) fail("conflict", "لم يُنجز إعداد النظام بعد.");
        const name = pStr(p, "name", 2, 40, "الاسم"), username = pStr(p, "username", 3, 20, "اسم المستخدم").toLowerCase(); checkUsername(username);
        if (await one(`SELECT 1 AS x FROM users WHERE username = $1`, [username])) fail("conflict", "اسم المستخدم مستخدم من قبل. اختر اسماً آخر.");
        const pass = checkPassword(p); if (p.role !== "supervisor" && p.role !== "viewer") fail("invalid", "اختر نوع الحساب.");
        if ((await one(`SELECT COUNT(*)::int AS n FROM users WHERE pending`)).n >= 30) fail("conflict", "يوجد عدد كبير من الطلبات بانتظار الاعتماد. راجع مدير النظام.");
        const r = await one(`INSERT INTO users (username, name, role, active, pending, pass, created_at) VALUES ($1,$2,$3,false,true,$4,$5) RETURNING *`, [username, name, p.role, hashPassword(pass), now()]);
        await audit(r, "signup", "user", r.id, "طلب حساب جديد بدور " + ROLES[p.role]); data = {ok: true};
      } else if (action === "auth.login"){
        const username = String(p.username || "").trim().toLowerCase().slice(0, 40), u = await one(`SELECT * FROM users WHERE username = $1`, [username]), t = now();
        if (u && N(u.locked_until) > t) fail("locked", "الحساب مقفل مؤقتاً بعد محاولات فاشلة متكررة. حاول بعد 5 دقائق أو راجع مدير النظام.");
        const okPass = verifyPassword(String(p.password || "").slice(0, 200), u ? u.pass : "");
        if (u && okPass && u.pending) fail("pending", "حسابك بانتظار اعتماد مدير النظام.");
        if (!u || !okPass || !u.active){
          if (u && u.active){ const f = Number(u.failed) + 1; if (f >= 5) await q(`UPDATE users SET failed = 0, locked_until = $1 WHERE id = $2`, [t + 300000, u.id]); else await q(`UPDATE users SET failed = $1 WHERE id = $2`, [f, u.id]); }
          await audit(u, "login.fail", "user", u ? u.id : null, "محاولة دخول فاشلة باسم: " + username.replace(/[^a-z0-9._-]/g, "?").slice(0, 20));
          fail("invalid", "اسم المستخدم أو كلمة المرور غير صحيحة.");
        }
        await q(`DELETE FROM sessions WHERE id = $1`, [s.id]); s = await newSession(res, req, u.id);
        await q(`UPDATE users SET failed = 0, last_login = $1 WHERE id = $2`, [t, u.id]); await audit(u, "login", "user", u.id, "تسجيل دخول"); data = {user: pub(u)};
      } else if (action === "auth.logout"){
        const u = await currentUser(s); if (u) await audit(u, "logout", "user", u.id, "تسجيل خروج"); await q(`UPDATE sessions SET user_id = NULL WHERE id = $1`, [s.id]); data = {ok: true};
      } else {
        const u = await currentUser(s); if (!u) fail("unauthenticated", "انتهت الجلسة. سجّل الدخول من جديد.");
        const h = Object.prototype.hasOwnProperty.call(H, action) ? H[action] : null;
        if (!h){ await audit(u, "denied", "api", action.slice(0, 40), `طلب مرفوض: إجراء غير معرّف (${action.slice(0, 40)})`); fail("forbidden", "إجراء غير معرّف في الخادم. لا يوجد أي إجراء لحذف أو تعديل السجلات المحمية."); }
        if (!PERMS[h[0]].includes(u.role)) await deny(u, h[0]);
        data = await h[1](u, p);
      }
    }
    return {ok: true, data, csrf: s.csrf};
  } catch(e){
    if (e instanceof ApiError) return {ok: false, code: e.code, message: e.message, csrf: s.csrf};
    console.error("api error:", e && e.message); return {ok: false, code: "server", message: "خطأ غير متوقع في الخادم.", csrf: s.csrf, status: 500};
  }
}
// الطلبات تُنفَّذ واحداً تلو الآخر حتى تبقى سلسلة سجل التدقيق متصلة ولا يتعارض استلام المناوبة.
let chain = Promise.resolve();
const serial = fn => { const r = chain.then(fn, fn); chain = r.catch(() => {}); return r; };

const STATIC = {"/": ["index.html", "text/html; charset=utf-8"], "/index.html": ["index.html", "text/html; charset=utf-8"], "/manifest.webmanifest": ["manifest.webmanifest", "application/manifest+json"], "/sw.js": ["sw.js", "text/javascript; charset=utf-8"],
  "/icon-192.png": ["icon-192.png", "image/png"], "/icon-512.png": ["icon-512.png", "image/png"], "/icon-maskable-512.png": ["icon-maskable-512.png", "image/png"], "/apple-touch-icon.png": ["apple-touch-icon.png", "image/png"]};
const send = (res, status, body, type) => { res.statusCode = status; res.setHeader("Content-Type", type); res.end(body); };

const server = http.createServer((req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff"); res.setHeader("X-Frame-Options", "DENY"); res.setHeader("Referrer-Policy", "same-origin");
  if (isHttps(req)) res.setHeader("Strict-Transport-Security", "max-age=31536000");
  const url = (req.url || "/").split("?")[0];
  if (req.method === "GET" || req.method === "HEAD"){
    if (url === "/healthz") return send(res, 200, "ok", "text/plain");
    const f = Object.prototype.hasOwnProperty.call(STATIC, url) ? STATIC[url] : null; if (!f) return send(res, 404, "Not found", "text/plain; charset=utf-8");
    return fs.readFile(path.join(__dirname, f[0]), (err, buf) => { if (err) return send(res, 404, "Not found", "text/plain"); res.setHeader("Cache-Control", f[0].endsWith(".png") ? "public, max-age=86400" : "no-cache"); send(res, 200, req.method === "HEAD" ? "" : buf, f[1]); });
  }
  if (req.method === "POST" && (url === "/api" || url === "/api/")){
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > 20000){ send(res, 413, JSON.stringify({ok: false, code: "invalid", message: "الطلب أكبر من المسموح."}), "application/json; charset=utf-8"); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { if (res.writableEnded) return;
      let body = null; try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch(e){}
      const action = body && typeof body.action === "string" ? body.action : "", p = body && body.payload && typeof body.payload === "object" && !Array.isArray(body.payload) ? body.payload : {};
      serial(() => handle(req, res, action, p)).then(out => { const st = out.status || 200; delete out.status; res.setHeader("Cache-Control", "no-store"); send(res, st, JSON.stringify(out), "application/json; charset=utf-8"); })
        .catch(e => { console.error("fatal:", e && e.message); if (!res.writableEnded) send(res, 500, JSON.stringify({ok: false, code: "server", message: "خطأ غير متوقع في الخادم."}), "application/json; charset=utf-8"); });
    });
    return;
  }
  send(res, 405, "Method not allowed", "text/plain");
});

migrate().then(() => { server.listen(PORT, "0.0.0.0", () => console.log("nabd listening on " + PORT)); setInterval(() => q(`DELETE FROM sessions WHERE last < $1`, [now() - 7 * 86400000]).catch(() => {}), 6 * 3600000).unref(); })
  .catch(e => { console.error("startup failed:", e && e.message); process.exit(1); });
