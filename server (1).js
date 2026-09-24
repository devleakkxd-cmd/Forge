// BotForge host. Run:  ADMIN_PASSWORD=yourpass node server.js   (Node 18+, no dependencies)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { spawn, execFile } = require('child_process');
const win = process.platform === 'win32';
const ROOT = path.join(__dirname, 'data'), PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '127.0.0.1';
const ORIGIN = process.env.ORIGIN || '*'; // your GitHub Pages origin, e.g. https://yourname.github.io
const CORS = { 'access-control-allow-origin': ORIGIN, 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS' };
fs.mkdirSync(ROOT, { recursive: true });

// Accounts: passwords are scrypt-hashed, sessions are signed tokens (30 days)
const UF = path.join(ROOT, 'users.json');
const users = (() => { try { return JSON.parse(fs.readFileSync(UF)); } catch { return {}; } })();
const SECRET = (() => { const f = path.join(ROOT, 'secret.key'); try { return fs.readFileSync(f); } catch { const k = crypto.randomBytes(32); fs.writeFileSync(f, k); return k; } })();
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const mkToken = u => { const x = u + '.' + (Date.now() + 30 * 864e5); return x + '.' + sign(x); };
const who = t => { const [u, x, s] = String(t || '').split('.'); return s && eq(sign(u + '.' + x), s) && +x > Date.now() && users[u] ? u : null; };
const tries = {};
const limited = ip => { const n = Date.now(), a = (tries[ip] || []).filter(t => n - t < 6e5); a.push(n); tries[ip] = a; return a.length > 10; };

const VENV = win ? '.venv\\Scripts\\' : '.venv/bin/';
const LANG = {
  'Node.js': {
    cmd: 'node index.js',
    install: 'npm install --no-audit --no-fund',
    files: {
      'index.js': 'const { Client, GatewayIntentBits } = require("discord.js");\nconst client = new Client({ intents: [GatewayIntentBits.Guilds] });\nclient.once("ready", () => console.log("Logged in as " + client.user.tag));\nclient.login(process.env.TOKEN);\n',
      'package.json': JSON.stringify({ name: 'bot', main: 'index.js', dependencies: { 'discord.js': '^14.16.3' } }, null, 2) + '\n'
    }
  },
  Python: {
    cmd: VENV + 'python -u main.py',
    install: `python${win ? '' : '3'} -m venv .venv && ${VENV}pip install -q -r requirements.txt`,
    files: {
      'main.py': 'import os\nimport discord\n\nclient = discord.Client(intents=discord.Intents.default())\n\n@client.event\nasync def on_ready():\n    print(f"Logged in as {client.user}", flush=True)\n\nclient.run(os.environ["TOKEN"])\n',
      'requirements.txt': 'discord.py>=2.4\n'
    }
  }
};

const bots = {};
const dir = id => path.join(ROOT, id);
const save = b => fs.writeFileSync(path.join(dir(b.id), 'bot.json'), JSON.stringify({ name: b.name, lang: b.lang, cmd: b.cmd, env: b.env, owner: b.owner }));
const runtime = m => ({ ...m, status: 'offline', start: 0, cpu: [], ram: [], logs: [], cl: new Set(), proc: null, stopping: false });
for (const id of fs.readdirSync(ROOT)) {
  try { bots[id] = runtime({ id, ...JSON.parse(fs.readFileSync(path.join(dir(id), 'bot.json'))) }); } catch {}
}

function emit(b, l, m) {
  const e = { l, m, t: new Date().toTimeString().slice(0, 8) };
  b.logs.push(e); if (b.logs.length > 500) b.logs.shift();
  for (const r of b.cl) r.write(`data: ${JSON.stringify(e)}\n\n`);
}

function sh(b, cmd, done) {
  emit(b, 'info', '$ ' + cmd);
  const env = { ...process.env, PYTHONUNBUFFERED: '1', FORCE_COLOR: '0' };
  b.env.forEach(e => { if (e.k) env[e.k] = e.v; });
  const p = spawn(cmd, { cwd: dir(b.id), shell: true, env, detached: !win });
  const pipe = (s, l) => { let buf = ''; s.on('data', d => { buf += d; const ls = buf.split(/\r?\n/); buf = ls.pop(); ls.forEach(x => x && emit(b, l, x)); }); };
  pipe(p.stdout, 'out'); pipe(p.stderr, 'out');
  p.on('error', e => emit(b, 'err', e.message));
  p.on('close', c => done(c));
  return p;
}

function fin(b) { b.status = 'offline'; b.start = 0; b.proc = null; b.cpu = []; b.ram = []; }

function start(b) {
  if (b.status !== 'offline') return;
  b.status = 'starting'; b.stopping = false;
  emit(b, 'info', 'Installing dependencies…');
  b.proc = sh(b, LANG[b.lang].install, c => {
    if (b.stopping || c !== 0) { if (!b.stopping) emit(b, 'err', 'Install failed (exit code ' + c + ')'); return fin(b); }
    emit(b, 'ok', 'Dependencies ready');
    b.status = 'online'; b.start = Date.now();
    b.proc = sh(b, b.cmd, c2 => { emit(b, b.stopping || c2 === 0 ? 'warn' : 'err', 'Process exited' + (c2 == null ? '' : ' with code ' + c2)); fin(b); });
  });
}

function stop(b) {
  const p = b.proc; if (!p) return;
  b.stopping = true; emit(b, 'warn', 'Stopping…');
  if (win) return execFile('taskkill', ['/pid', p.pid, '/T', '/F'], () => {});
  try { process.kill(-p.pid, 'SIGTERM'); } catch {}
  setTimeout(() => { try { process.kill(-p.pid, 'SIGKILL'); } catch {} }, 5000).unref();
}

function restart(b) {
  stop(b);
  const w = setInterval(() => { if (b.status === 'offline') { clearInterval(w); start(b); } }, 250);
}

function usage(pid, cb) {
  if (win) return cb(0, 0);
  execFile('ps', ['-eo', 'pid=,ppid=,%cpu=,rss='], (e, out) => {
    if (e) return cb(0, 0);
    const rows = out.trim().split('\n').map(l => l.trim().split(/\s+/).map(Number));
    const ids = new Set([pid]); let grew = true;
    while (grew) { grew = false; for (const [r, pp] of rows) if (ids.has(pp) && !ids.has(r)) { ids.add(r); grew = true; } }
    let c = 0, m = 0; for (const [r, , cp, rs] of rows) if (ids.has(r)) { c += cp; m += rs / 1024; }
    cb(+c.toFixed(1), Math.round(m));
  });
}
setInterval(() => Object.values(bots).forEach(b => {
  if (b.status !== 'online' || !b.proc) return;
  usage(b.proc.pid, (c, m) => { b.cpu.push(c); b.ram.push(m); if (b.cpu.length > 30) { b.cpu.shift(); b.ram.shift(); } });
}), 2000);

const view = b => ({ id: b.id, name: b.name, lang: b.lang, cmd: b.cmd, env: b.env, status: b.status, start: b.start, cpu: b.cpu, ram: b.ram });
const send = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json', ...CORS }); res.end(JSON.stringify(obj)); };
const okName = /^[\w.-]+$/;
http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
  const url = new URL(req.url, 'http://x'), p = url.pathname.split('/').filter(Boolean);
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',')[0].trim();
  try {
    if (!p.length) { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(fs.readFileSync(path.join(__dirname, 'index.html'))); }
    if (p[0] !== 'api') return send(res, 404, { error: 'Not found' });
    let body = {};
    if (req.method !== 'GET' && req.method !== 'DELETE') { let s = ''; for await (const c of req) s += c; body = s ? JSON.parse(s) : {}; }

    if (p[1] === 'signup' || p[1] === 'login') {
      if (limited(ip)) throw new Error('Too many attempts. Try again in a few minutes.');
      const name = String(body.username || '').toLowerCase(), pw = String(body.password || '');
      if (p[1] === 'signup') {
        if (Object.keys(users).length && process.env.OPEN_SIGNUP !== '1') throw new Error('Sign-ups are closed on this server');
        if (!/^[a-z0-9_]{3,20}$/.test(name)) throw new Error('Username: 3-20 letters, numbers or _');
        if (pw.length < 8) throw new Error('Password must be at least 8 characters');
        if (users[name]) throw new Error('That username is taken');
        const salt = crypto.randomBytes(16).toString('hex');
        users[name] = { salt, hash: hash(pw, salt) }; fs.writeFileSync(UF, JSON.stringify(users));
        Object.values(bots).forEach(b => { if (!b.owner) { b.owner = name; save(b); } });
      } else if (!users[name] || !eq(users[name].hash, hash(pw, users[name].salt))) return send(res, 401, { error: 'Wrong username or password' });
      return send(res, 200, { token: mkToken(name), user: name });
    }

    const user = who((req.headers.authorization || '').replace('Bearer ', '') || url.searchParams.get('token'));
    if (!user) return send(res, 401, { error: 'Please sign in' });
    if (p[1] !== 'bots') return send(res, 404, { error: 'Not found' });

    if (p.length === 2) {
      if (req.method === 'GET') return send(res, 200, Object.values(bots).filter(b => b.owner === user).map(view));
      const L = LANG[body.lang]; if (!L) throw new Error('Pick Node.js or Python');
      const name = String(body.name || 'My bot').slice(0, 40);
      const id = (name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'bot') + '-' + crypto.randomBytes(2).toString('hex');
      fs.mkdirSync(dir(id));
      for (const [f, c] of Object.entries(L.files)) fs.writeFileSync(path.join(dir(id), f), c);
      bots[id] = runtime({ id, name, lang: body.lang, cmd: L.cmd, owner: user, env: [{ k: 'TOKEN', v: '', h: true }] });
      save(bots[id]); return send(res, 200, view(bots[id]));
    }

    const b = bots[p[2]]; if (!b || b.owner !== user) return send(res, 404, { error: 'Bot not found' });
    const act = p[3];
    if (!act) {
      if (req.method === 'DELETE') { stop(b); delete bots[b.id]; setTimeout(() => fs.rmSync(dir(b.id), { recursive: true, force: true }), 1500); return send(res, 200, {}); }
      if (body.name) b.name = String(body.name).slice(0, 40);
      if (body.cmd) b.cmd = String(body.cmd);
      if (Array.isArray(body.env)) b.env = body.env.map(e => ({ k: String(e.k), v: String(e.v), h: !!e.h }));
      save(b); return send(res, 200, view(b));
    }
    if (act === 'start') { start(b); return send(res, 200, {}); }
    if (act === 'stop') { stop(b); return send(res, 200, {}); }
    if (act === 'restart') { restart(b); return send(res, 200, {}); }
    if (act === 'stdin') {
      if (b.status !== 'online' || !b.proc) throw new Error('Start the bot first');
      b.proc.stdin.write(String(body.line) + '\n'); emit(b, 'info', '> ' + body.line); return send(res, 200, {});
    }
    if (act === 'logs') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', ...CORS });
      b.logs.forEach(e => res.write(`data: ${JSON.stringify(e)}\n\n`));
      b.cl.add(res); req.on('close', () => b.cl.delete(res)); return;
    }
    if (act === 'files') {
      if (req.method === 'GET') {
        const out = {};
        for (const f of fs.readdirSync(dir(b.id), { withFileTypes: true }))
          if (f.isFile() && !/^(bot\.json|package-lock\.json)$/.test(f.name) && fs.statSync(path.join(dir(b.id), f.name)).size < 2e5)
            out[f.name] = fs.readFileSync(path.join(dir(b.id), f.name), 'utf8');
        return send(res, 200, out);
      }
      if (!okName.test(p[4] || '') || p[4] === 'bot.json') throw new Error('Invalid file name');
      fs.writeFileSync(path.join(dir(b.id), p[4]), String(body.content ?? '')); return send(res, 200, {});
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, 400, { error: e.message }); }
}).listen(PORT, HOST, () => console.log(`BotForge running at http://${HOST}:${PORT}\nThe first account you sign up becomes the admin.${process.env.OPEN_SIGNUP === '1' ? '\nOPEN_SIGNUP is on: anyone can create an account and run code here.' : ''}`));
