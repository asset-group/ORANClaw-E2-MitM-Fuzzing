const fs = require('fs');
let content = fs.readFileSync('src/App.tsx', 'utf8');

const replacements = [
  /dark:text-indigo-400 dark:text-indigo-400/g,
  /dark:text-slate-100 dark:text-slate-100/g,
  /dark:text-slate-400 dark:text-slate-400/g,
  /dark:border-slate-800 dark:border-slate-800/g,
  /dark:bg-slate-900 dark:bg-slate-900/g,
  /dark:bg-slate-800 dark:bg-slate-800/g,
  /dark:bg-slate-950 dark:bg-slate-800\/50/g,
  /dark:hover:bg-slate-700 dark:hover:bg-slate-700/g
];

const replacementValues = [
  'dark:text-indigo-400',
  'dark:text-slate-100',
  'dark:text-slate-400',
  'dark:border-slate-800',
  'dark:bg-slate-900',
  'dark:bg-slate-800',
  'dark:bg-slate-800/50',
  'dark:hover:bg-slate-700'
];

for (let i = 0; i < replacements.length; i++) {
  content = content.replace(replacements[i], replacementValues[i]);
}

fs.writeFileSync('src/App.tsx', content);
console.log('Done');
