'use strict';
/* 마이SNS - 브라우저 저장소(IndexedDB) 기반 SNS
   - 로그인: PBKDF2 해시 (비밀번호 평문 저장 안 함)
   - 비밀일기: 비밀번호에서 만든 키로 AES-GCM 암호화 */

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const enc = new TextEncoder(), dec = new TextDecoder();

// ---------- IndexedDB ----------
let dbp;
function db() {
  if (dbp) return dbp;
  dbp = new Promise((res, rej) => {
    const r = indexedDB.open('mysns', 1);
    r.onupgradeneeded = () => {
      const d = r.result;
      d.createObjectStore('users', { keyPath: 'username' });
      d.createObjectStore('photos', { keyPath: 'id' });
      d.createObjectStore('diary', { keyPath: 'id' });
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  return dbp;
}
async function tx(store, mode, fn) {
  const d = await db();
  return new Promise((res, rej) => {
    const t = d.transaction(store, mode);
    const out = fn(t.objectStore(store));
    t.oncomplete = () => res(out.result);
    t.onerror = () => rej(t.error);
  });
}
const dbGet = (s, k) => tx(s, 'readonly', (o) => o.get(k));
const dbAll = (s) => tx(s, 'readonly', (o) => o.getAll());
const dbPut = (s, v) => tx(s, 'readwrite', (o) => o.put(v));
const dbDel = (s, k) => tx(s, 'readwrite', (o) => o.delete(k));

// ---------- Crypto ----------
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function deriveBits(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  return { k, salt };
}
async function hashPw(pw, salt) {
  const { k } = await deriveBits(pw, salt);
  return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, k, 256));
}
async function deriveKey(pw, salt) {
  const { k } = await deriveBits(pw, salt);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, k,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), data: b64(ct) };
}
async function decryptJSON(key, rec) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(rec.iv) }, key, unb64(rec.data));
  return JSON.parse(dec.decode(pt));
}

// ---------- 상태 ----------
let me = null;        // 로그인한 아이디
let diaryKey = null;  // 메모리에만 보관 (새로고침하면 다시 로그인)
let mode = 'login';
let openPhotoId = null;

function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add('hidden'), 2200);
}
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const fmt = (ts) => new Date(ts).toLocaleString('ko-KR', { dateStyle: 'medium', timeStyle: 'short' });

// ---------- 인증 ----------
function setMode(m) {
  mode = m;
  $('#tabLogin').classList.toggle('active', m === 'login');
  $('#tabSignup').classList.toggle('active', m === 'signup');
  $('#pw2Row').classList.toggle('hidden', m === 'login');
  $('#password2').required = m === 'signup';
  $('#password').autocomplete = m === 'login' ? 'current-password' : 'new-password';
  $('#authSubmit').textContent = m === 'login' ? '로그인' : '가입하기';
  $('#authMsg').textContent = '';
}
$('#tabLogin').onclick = () => setMode('login');
$('#tabSignup').onclick = () => setMode('signup');

$('#authForm').onsubmit = async (e) => {
  e.preventDefault();
  const username = $('#username').value.trim();
  const pw = $('#password').value;
  const msg = $('#authMsg'); msg.textContent = '';
  const btn = $('#authSubmit'); btn.disabled = true;
  try {
    if (mode === 'signup') {
      if (pw !== $('#password2').value) throw new Error('비밀번호가 일치하지 않습니다.');
      if (await dbGet('users', username)) throw new Error('이미 사용 중인 아이디입니다.');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const kdfSalt = crypto.getRandomValues(new Uint8Array(16));
      await dbPut('users', { username, salt: b64(salt), kdfSalt: b64(kdfSalt), hash: await hashPw(pw, salt), created: Date.now() });
      toast('가입 완료! 로그인합니다.');
    }
    const u = await dbGet('users', username);
    if (!u || (await hashPw(pw, unb64(u.salt))) !== u.hash) throw new Error('아이디 또는 비밀번호가 올바르지 않습니다.');
    diaryKey = await deriveKey(pw, unb64(u.kdfSalt));
    me = username;
    sessionStorage.setItem('mysns_user', me);
    $('#authForm').reset();
    showMain();
  } catch (err) {
    msg.textContent = err.message;
  } finally { btn.disabled = false; }
};

$('#logoutBtn').onclick = () => {
  me = null; diaryKey = null; sessionStorage.removeItem('mysns_user');
  $('#mainView').classList.add('hidden');
  $('#authView').classList.remove('hidden');
  setMode('login');
};

function showMain() {
  $('#authView').classList.add('hidden');
  $('#mainView').classList.remove('hidden');
  $('#whoami').textContent = me + ' 님';
  $('#diaryDate').value = new Date().toISOString().slice(0, 10);
  go('feed');
}

// ---------- 화면 전환 ----------
function go(view) {
  $$('.nav').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $$('.view').forEach((v) => v.classList.add('hidden'));
  $('#' + view + 'View').classList.remove('hidden');
  if (view === 'feed') renderFeed();
  if (view === 'album') renderAlbum();
  if (view === 'diary') renderDiary();
}
$$('.nav').forEach((b) => (b.onclick = () => go(b.dataset.view)));

// ---------- 사진 ----------
function resizeImage(file, max = 1280) {
  return new Promise((res, rej) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      const r = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = Math.round(img.width * r); c.height = Math.round(img.height * r);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      URL.revokeObjectURL(url);
      res(c.toDataURL('image/jpeg', 0.85));
    };
    img.onerror = () => rej(new Error('이미지를 읽을 수 없습니다: ' + file.name));
    img.src = url;
  });
}

$('#photoForm').onsubmit = async (e) => {
  e.preventDefault();
  const files = [...$('#photoFiles').files];
  const btn = e.submitter; btn.disabled = true; btn.textContent = '올리는 중...';
  try {
    for (const f of files) {
      const src = await resizeImage(f);
      await dbPut('photos', {
        id: uid(), owner: me, src, caption: $('#photoCaption').value.trim(),
        vis: $('#photoVis').value, created: Date.now(), likes: [], comments: [],
      });
    }
    e.target.reset();
    toast(files.length + '장 업로드 완료');
    renderAlbum();
  } catch (err) { toast(err.message); }
  finally { btn.disabled = false; btn.textContent = '사진 올리기'; }
};

const byNew = (a, b) => b.created - a.created;

async function renderAlbum() {
  const list = (await dbAll('photos')).filter((p) => p.owner === me).sort(byNew);
  const g = $('#albumGrid'); g.innerHTML = '';
  $('#albumEmpty').classList.toggle('hidden', list.length > 0);
  for (const p of list) {
    const t = document.createElement('div'); t.className = 'tile';
    const img = new Image(); img.src = p.src; img.alt = p.caption;
    const badge = document.createElement('span'); badge.className = 'badge';
    badge.textContent = p.vis === 'public' ? '🌍 공개' : '🔒 비공개';
    const del = document.createElement('button'); del.className = 'del'; del.textContent = '🗑'; del.title = '삭제';
    del.onclick = async (ev) => {
      ev.stopPropagation();
      if (confirm('이 사진을 삭제할까요?')) { await dbDel('photos', p.id); renderAlbum(); }
    };
    t.onclick = () => openPhoto(p.id);
    t.append(img, badge, del); g.append(t);
  }
}

async function renderFeed() {
  const list = (await dbAll('photos')).filter((p) => p.vis === 'public').sort(byNew);
  const g = $('#feedGrid'); g.innerHTML = '';
  $('#feedEmpty').classList.toggle('hidden', list.length > 0);
  for (const p of list) {
    const d = document.createElement('article'); d.className = 'post';
    const head = document.createElement('div'); head.className = 'post-head'; head.textContent = '👤 ' + p.owner;
    const img = new Image(); img.src = p.src; img.alt = p.caption; img.onclick = () => openPhoto(p.id);
    const body = document.createElement('div'); body.className = 'post-body';
    const like = document.createElement('button'); like.className = 'like';
    const setLike = () => (like.textContent = (p.likes.includes(me) ? '❤️ ' : '🤍 ') + p.likes.length);
    setLike();
    like.onclick = async () => { await toggleLike(p); setLike(); };
    const cmt = document.createElement('button'); cmt.className = 'like'; cmt.textContent = '💬 ' + p.comments.length;
    cmt.onclick = () => openPhoto(p.id);
    const cap = document.createElement('p'); cap.className = 'cap'; cap.textContent = p.caption;
    const time = document.createElement('div'); time.className = 'time'; time.textContent = fmt(p.created);
    body.append(like, cmt, cap, time);
    d.append(head, img, body); g.append(d);
  }
}

async function toggleLike(p) {
  const fresh = await dbGet('photos', p.id);
  const i = fresh.likes.indexOf(me);
  i >= 0 ? fresh.likes.splice(i, 1) : fresh.likes.push(me);
  await dbPut('photos', fresh);
  p.likes = fresh.likes;
}

async function openPhoto(id) {
  const p = await dbGet('photos', id);
  if (!p) return;
  openPhotoId = id;
  $('#lbImg').src = p.src;
  const meta = $('#lbMeta'); meta.innerHTML = '';
  const h = document.createElement('strong'); h.textContent = '👤 ' + p.owner;
  const c = document.createElement('p'); c.textContent = p.caption;
  const t = document.createElement('small'); t.textContent = fmt(p.created);
  meta.append(h, c, t);
  const box = $('#lbComments'); box.innerHTML = '';
  for (const cm of p.comments) {
    const line = document.createElement('p');
    const b = document.createElement('strong'); b.textContent = cm.user + ' ';
    line.append(b, document.createTextNode(cm.text)); box.append(line);
  }
  $('#lightbox').classList.remove('hidden');
}
function closePhoto() {
  $('#lightbox').classList.add('hidden'); openPhotoId = null;
  if (!$('#feedView').classList.contains('hidden')) renderFeed();
}
$('#lbClose').onclick = closePhoto;
$('#lightbox').onclick = (e) => { if (e.target.id === 'lightbox') closePhoto(); };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePhoto(); });
$('#commentForm').onsubmit = async (e) => {
  e.preventDefault();
  const p = await dbGet('photos', openPhotoId);
  p.comments.push({ user: me, text: $('#commentInput').value.trim(), at: Date.now() });
  await dbPut('photos', p);
  $('#commentInput').value = '';
  openPhoto(openPhotoId);
};

// ---------- 비밀 일기 ----------
$('#diaryForm').onsubmit = async (e) => {
  e.preventDefault();
  const editId = $('#diaryEditId').value;
  const payload = {
    title: $('#diaryTitle').value.trim(), body: $('#diaryBody').value,
    mood: $('#diaryMood').value, date: $('#diaryDate').value,
  };
  const sealed = await encryptJSON(diaryKey, payload);
  const old = editId ? await dbGet('diary', editId) : null;
  await dbPut('diary', { id: editId || uid(), owner: me, created: old ? old.created : Date.now(), ...sealed });
  resetDiaryForm(); toast('일기가 암호화되어 저장되었어요 🔒'); renderDiary();
};
function resetDiaryForm() {
  $('#diaryForm').reset(); $('#diaryEditId').value = '';
  $('#diaryDate').value = new Date().toISOString().slice(0, 10);
  $('#diarySave').textContent = '저장';
}
$('#diaryCancel').onclick = resetDiaryForm;

async function renderDiary() {
  const recs = (await dbAll('diary')).filter((r) => r.owner === me);
  const items = [];
  for (const r of recs) {
    try { items.push({ r, d: await decryptJSON(diaryKey, r) }); } catch { /* 복호화 실패 무시 */ }
  }
  items.sort((a, b) => (b.d.date + b.r.created).localeCompare(a.d.date + a.r.created));
  const box = $('#diaryList'); box.innerHTML = '';
  $('#diaryEmpty').classList.toggle('hidden', items.length > 0);
  for (const { r, d } of items) {
    const el = document.createElement('div'); el.className = 'entry';
    const h = document.createElement('h3'); h.textContent = d.mood + ' ' + d.title;
    const m = document.createElement('div'); m.className = 'meta'; m.textContent = d.date;
    const b = document.createElement('div'); b.className = 'body'; b.textContent = d.body;
    const acts = document.createElement('div'); acts.className = 'acts';
    const ed = document.createElement('button'); ed.className = 'btn small'; ed.textContent = '수정';
    ed.onclick = () => {
      $('#diaryEditId').value = r.id; $('#diaryTitle').value = d.title; $('#diaryBody').value = d.body;
      $('#diaryMood').value = d.mood; $('#diaryDate').value = d.date; $('#diarySave').textContent = '수정 저장';
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };
    const de = document.createElement('button'); de.className = 'btn small danger'; de.textContent = '삭제';
    de.onclick = async () => { if (confirm('이 일기를 삭제할까요?')) { await dbDel('diary', r.id); renderDiary(); } };
    acts.append(ed, de);
    el.append(h, m, b, acts); box.append(el);
  }
}

// ---------- 시작 ----------
// 일기 키는 메모리에만 있으므로 새로고침 시 항상 로그인 화면으로
sessionStorage.removeItem('mysns_user');
$('#authView').classList.remove('hidden');
setMode('login');
