'use strict';
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const cors    = require('cors');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'cj-secret-2024';

/* ═══════════════════════════════
   폴더 초기화
═══════════════════════════════ */
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PDFS_DIR    = path.join(__dirname, 'pdfs');
const DATA_DIR    = path.join(__dirname, 'data');
[UPLOADS_DIR, PDFS_DIR, DATA_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

/* ═══════════════════════════════
   JSON 파일 DB (네이티브 의존성 없음)
═══════════════════════════════ */
const DB_FILES = {
  users:   path.join(DATA_DIR, 'users.json'),
  reports: path.join(DATA_DIR, 'reports.json'),
  photos:  path.join(DATA_DIR, 'photos.json'),
};

function readDB(name) {
  try { return JSON.parse(fs.readFileSync(DB_FILES[name], 'utf8')); }
  catch { return []; }
}
function writeDB(name, data) {
  fs.writeFileSync(DB_FILES[name], JSON.stringify(data, null, 2), 'utf8');
}
function nextId(arr) {
  return arr.length ? Math.max(...arr.map(r => r.id)) + 1 : 1;
}
function now() {
  return new Date().toLocaleString('ko-KR', { hour12: false }).replace(/\. /g, '-').replace('.', '');
}

/* ═══════════════════════════════
   기본 관리자 계정
═══════════════════════════════ */
{
  const users = readDB('users');
  if (!users.find(u => u.role === 'admin')) {
    users.push({ id: 1, username: 'admin', password: bcrypt.hashSync('admin1234', 10), name: '관리자', role: 'admin', created_at: now() });
    writeDB('users', users);
    console.log('✅ 기본 관리자 생성: admin / admin1234');
  }
}

/* ═══════════════════════════════
   미들웨어
═══════════════════════════════ */
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/pdfs',    express.static(PDFS_DIR));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, file.fieldname === 'pdf' ? PDFS_DIR : UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const ext = path.extname(file.originalname) || (file.fieldname === 'pdf' ? '.pdf' : '.jpg');
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2,7)}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: '세션이 만료되었습니다' }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: '관리자만 접근 가능합니다' });
  next();
}

/* ═══════════════════════════════
   인증
═══════════════════════════════ */
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = readDB('users').find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다' });
  const token = jwt.sign({ id: user.id, username: user.username, name: user.name, role: user.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role } });
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = readDB('users').find(u => u.id === req.user.id);
  res.json(u ? { id: u.id, username: u.username, name: u.name, role: u.role } : {});
});

/* ═══════════════════════════════
   사용자 관리
═══════════════════════════════ */
app.get('/api/users', auth, adminOnly, (req, res) => {
  res.json(readDB('users').map(({ password, ...u }) => u));
});

app.post('/api/users', auth, adminOnly, (req, res) => {
  const { username, password, name, role } = req.body || {};
  if (!username || !password || !name || !['worker','admin'].includes(role))
    return res.status(400).json({ error: '모든 항목을 입력하세요' });
  const users = readDB('users');
  if (users.find(u => u.username === username))
    return res.status(409).json({ error: '이미 사용 중인 아이디입니다' });
  const newUser = { id: nextId(users), username, password: bcrypt.hashSync(password, 10), name, role, created_at: now() };
  users.push(newUser);
  writeDB('users', users);
  res.json({ id: newUser.id, username, name, role });
});

app.put('/api/users/:id/password', auth, adminOnly, (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 4) return res.status(400).json({ error: '비밀번호는 4자 이상' });
  const users = readDB('users');
  const idx = users.findIndex(u => u.id === Number(req.params.id));
  if (idx < 0) return res.status(404).json({ error: '없음' });
  users[idx].password = bcrypt.hashSync(password, 10);
  writeDB('users', users);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  if (String(req.user.id) === req.params.id)
    return res.status(400).json({ error: '자기 자신은 삭제 불가' });
  const users = readDB('users').filter(u => u.id !== Number(req.params.id));
  writeDB('users', users);
  res.json({ ok: true });
});

/* ═══════════════════════════════
   보고서
═══════════════════════════════ */
app.post('/api/reports', auth,
  upload.fields([{ name: 'photos', maxCount: 60 }, { name: 'pdf', maxCount: 1 }]),
  (req, res) => {
    let meta, photosMeta;
    try { meta = JSON.parse(req.body.meta || '{}'); photosMeta = JSON.parse(req.body.photos_meta || '[]'); }
    catch { return res.status(400).json({ error: '데이터 파싱 오류' }); }

    const reports = readDB('reports');
    const newReport = {
      id: nextId(reports),
      project_name: meta.project_name || '무제',
      site_name:    meta.site_name    || '',
      work_date:    meta.work_date    || '',
      weather:      meta.weather      || '',
      temperature:  meta.temperature  || '',
      work_type:    meta.work_type    || '',
      notes:        meta.notes        || '',
      worker_id:    req.user.id,
      worker_name:  req.user.name,
      status:       'submitted',
      pdf_filename: req.files?.pdf?.[0]?.filename || null,
      created_at:   now(),
      updated_at:   now(),
    };
    reports.push(newReport);
    writeDB('reports', reports);

    const photos = readDB('photos');
    const photoFiles = req.files?.photos || [];
    photoFiles.forEach((file, i) => {
      const pm = photosMeta[i] || {};
      photos.push({
        id:             nextId(photos),
        report_id:      newReport.id,
        filename:       file.filename,
        original_name:  pm.original_name || file.originalname,
        exif_timestamp: pm.timestamp     || null,
        description:    pm.description   || '',
        is_main:        pm.is_main ? 1 : 0,
        sort_order:     pm.sort_order ?? i,
      });
    });
    writeDB('photos', photos);
    res.json({ id: newReport.id, ok: true });
  }
);

app.get('/api/reports', auth, (req, res) => {
  const allPhotos  = readDB('photos');
  let reports = readDB('reports');
  if (req.user.role !== 'admin') reports = reports.filter(r => r.worker_id === req.user.id);
  reports = reports.sort((a, b) => b.id - a.id).map(r => ({
    ...r,
    photo_count: allPhotos.filter(p => p.report_id === r.id).length
  }));
  res.json(reports);
});

app.get('/api/reports/:id', auth, (req, res) => {
  const id     = Number(req.params.id);
  const report = readDB('reports').find(r => r.id === id);
  if (!report) return res.status(404).json({ error: '없음' });
  if (req.user.role !== 'admin' && report.worker_id !== req.user.id)
    return res.status(403).json({ error: '권한 없음' });
  const photos = readDB('photos').filter(p => p.report_id === id)
    .sort((a, b) => (a.sort_order - b.sort_order) || (a.exif_timestamp - b.exif_timestamp));
  res.json({ ...report, photos });
});

app.put('/api/reports/:id', auth, (req, res) => {
  const id      = Number(req.params.id);
  const reports = readDB('reports');
  const idx     = reports.findIndex(r => r.id === id);
  if (idx < 0) return res.status(404).json({ error: '없음' });
  // 작업자는 자신의 보고서만, 관리자는 전체
  if (req.user.role !== 'admin' && reports[idx].worker_id !== req.user.id)
    return res.status(403).json({ error: '권한 없음' });
  const { project_name, site_name, work_date, weather, temperature, work_type, notes, status } = req.body || {};
  const update = { project_name, site_name, work_date, weather, temperature, work_type, notes, updated_at: now() };
  // status 변경은 관리자만
  if (req.user.role === 'admin' && status) update.status = status;
  Object.assign(reports[idx], update);
  writeDB('reports', reports);
  res.json({ ok: true });
});

app.put('/api/reports/:id/pdf', auth, adminOnly, upload.single('pdf'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'PDF 없음' });
  const id      = Number(req.params.id);
  const reports = readDB('reports');
  const idx     = reports.findIndex(r => r.id === id);
  if (idx < 0) return res.status(404).json({ error: '없음' });
  if (reports[idx].pdf_filename) {
    try { fs.unlinkSync(path.join(PDFS_DIR, reports[idx].pdf_filename)); } catch {}
  }
  reports[idx].pdf_filename = req.file.filename;
  reports[idx].updated_at   = now();
  writeDB('reports', reports);
  res.json({ ok: true, filename: req.file.filename });
});

app.delete('/api/reports/:id', auth, adminOnly, (req, res) => {
  const id     = Number(req.params.id);
  const report = readDB('reports').find(r => r.id === id);
  if (!report) return res.status(404).json({ error: '없음' });
  readDB('photos').filter(p => p.report_id === id).forEach(p => {
    try { fs.unlinkSync(path.join(UPLOADS_DIR, p.filename)); } catch {}
  });
  if (report.pdf_filename) { try { fs.unlinkSync(path.join(PDFS_DIR, report.pdf_filename)); } catch {} }
  writeDB('reports', readDB('reports').filter(r => r.id !== id));
  writeDB('photos',  readDB('photos').filter(p => p.report_id !== id));
  res.json({ ok: true });
});

/* ═══════════════════════════════
   사진 수정
═══════════════════════════════ */
app.put('/api/photos/:id', auth, (req, res) => {
  const id     = Number(req.params.id);
  const photos = readDB('photos');
  const idx    = photos.findIndex(p => p.id === id);
  if (idx < 0) return res.status(404).json({ error: '없음' });
  // 해당 사진의 보고서 소유자 확인
  const report = readDB('reports').find(r => r.id === photos[idx].report_id);
  if (req.user.role !== 'admin' && report?.worker_id !== req.user.id)
    return res.status(403).json({ error: '권한 없음' });
  const { description, is_main } = req.body || {};
  if (is_main) {
    const rid = photos[idx].report_id;
    photos.forEach(p => { if (p.report_id === rid) p.is_main = 0; });
  }
  photos[idx].description = description ?? photos[idx].description;
  if (is_main !== undefined) photos[idx].is_main = is_main ? 1 : 0;
  writeDB('photos', photos);
  res.json({ ok: true });
});

/* ═══════════════════════════════
   시작
═══════════════════════════════ */
app.listen(PORT, () => {
  console.log(`\n🏗️  공사현장 사진 일지 서버 실행 중`);
  console.log(`   작업자: http://localhost:${PORT}/worker.html`);
  console.log(`   관리자: http://localhost:${PORT}/admin.html\n`);
});
