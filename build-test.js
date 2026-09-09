const fs = require('fs');
const { input } = require('./test-dnel.js');
const { build, validate } = require('./qea-doc');

const v = validate(input);
console.log('\n── validate ──');
console.log('ok:', v.ok, '| reconciles:', v.reconciles, '| outstanding TODOs:', v.todos.length);
if (v.todos.length) v.todos.forEach(t => console.log('   ', t.path, '—', t.text.slice(0, 70)));
if (!v.reconciles) console.log('   RECONCILE MISMATCH:', JSON.stringify(v.reconcile));

build(input).then(({ buffer, sections }) => {
  fs.writeFileSync('/tmp/qea.docx', buffer);
  console.log('\n── built ──');
  console.log('bytes:', buffer.length);
  console.log('sections:', sections.map(s => s.title).join(' · '));
}).catch(e => { console.error('BUILD FAILED:', e.message); process.exit(1); });
