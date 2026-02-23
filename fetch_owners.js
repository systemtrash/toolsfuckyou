// fetch_owners.js
// Usage: BOT_TOKEN=your_bot_token node fetch_owners.js
// Writes owners.json in the same folder with structure { "<id>": { name, avatar } }

const fs = require('fs');
const https = require('https');

const OWNER_IDS = ['207819716973166592','563720915473530890','1471505228023992538'];
const TOKEN = process.env.BOT_TOKEN;
if (!TOKEN) {
  console.error('Provide BOT_TOKEN env variable.');
  process.exit(1);
}

function apiGet(path){
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'discord.com',
      path,
      method: 'GET',
      headers: { Authorization: `Bot ${TOKEN}` }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(JSON.parse(data));
        else reject(new Error('Status ' + res.statusCode + ': ' + data));
      });
    });
    req.on('error', reject);
    req.end();
  });
}

(async function(){
  const out = {};
  for (const id of OWNER_IDS){
    try{
      const user = await apiGet(`/api/v10/users/${id}`);
      // build avatar url
      const avatar = user.avatar ? `https://cdn.discordapp.com/avatars/${id}/${user.avatar}.png?size=128` : `https://cdn.discordapp.com/embed/avatars/${user.discriminator % 5}.png`;
      out[id] = { name: `${user.username}#${user.discriminator}`, avatar };
      console.log('Fetched', id, out[id].name);
    }catch(e){
      console.error('Failed for', id, e.message);
    }
  }
  fs.writeFileSync('owners.json', JSON.stringify(out, null, 2));
  console.log('owners.json written. Place it next to index.html and open via HTTP server (or use local dev server).');
})();
