const fs = require('fs');

let content = fs.readFileSync('src/App.tsx', 'utf8');

// We only want to replace classes after the header, so let's split the file
const parts = content.split('</header>');
if (parts.length < 2) {
  console.log("Could not find </header>");
  process.exit(1);
}

let restOfFile = parts[1];

// Function to safely replace classes
function replaceClass(source, target, replacement) {
  // Use regex to match exact class names within className strings
  // We need to be careful not to replace parts of other classes
  const regex = new RegExp(`(className="[^"]*\\b)${target}(\\b[^"]*")`, 'g');
  return source.replace(regex, `$1${replacement}$2`);
}

// Apply replacements to restOfFile
restOfFile = replaceClass(restOfFile, 'bg-white', 'bg-white dark:bg-slate-900');
restOfFile = replaceClass(restOfFile, 'bg-slate-50', 'bg-slate-50 dark:bg-slate-950');
restOfFile = replaceClass(restOfFile, 'text-slate-900', 'text-slate-900 dark:text-slate-100');
restOfFile = replaceClass(restOfFile, 'text-slate-600', 'text-slate-600 dark:text-slate-400');
restOfFile = replaceClass(restOfFile, 'border-slate-200', 'border-slate-200 dark:border-slate-800');
restOfFile = replaceClass(restOfFile, 'bg-indigo-600', 'bg-indigo-600 dark:bg-indigo-500');
restOfFile = replaceClass(restOfFile, 'text-indigo-600', 'text-indigo-600 dark:text-indigo-400');
restOfFile = replaceClass(restOfFile, 'bg-amber-50', 'bg-amber-50 dark:bg-amber-950/30');
restOfFile = replaceClass(restOfFile, 'border-amber-200', 'border-amber-200 dark:border-amber-900/50');
restOfFile = replaceClass(restOfFile, 'text-amber-800', 'text-amber-800 dark:text-amber-200');
restOfFile = replaceClass(restOfFile, 'bg-slate-200', 'bg-slate-200 dark:bg-slate-800');
restOfFile = replaceClass(restOfFile, 'hover:bg-slate-300', 'hover:bg-slate-300 dark:hover:bg-slate-700');
restOfFile = replaceClass(restOfFile, 'bg-indigo-100', 'bg-indigo-100 dark:bg-indigo-900/50');
restOfFile = replaceClass(restOfFile, 'text-indigo-700', 'text-indigo-700 dark:text-indigo-300');
restOfFile = replaceClass(restOfFile, 'text-slate-500', 'text-slate-500 dark:text-slate-400');
restOfFile = replaceClass(restOfFile, 'hover:bg-white', 'hover:bg-white dark:hover:bg-slate-800');
restOfFile = replaceClass(restOfFile, 'hover:text-slate-900', 'hover:text-slate-900 dark:hover:text-slate-100');
restOfFile = replaceClass(restOfFile, 'bg-slate-100', 'bg-slate-100 dark:bg-slate-800');

// Also need to fix the FileTreeItem and CodeBlock which are before </header>
let beforeHeader = parts[0];
beforeHeader = replaceClass(beforeHeader, 'hover:bg-slate-800/50', 'hover:bg-slate-800/50 dark:hover:bg-slate-800/80');
beforeHeader = replaceClass(beforeHeader, 'text-slate-200', 'text-slate-200 dark:text-slate-100');
beforeHeader = replaceClass(beforeHeader, 'text-slate-300', 'text-slate-300 dark:text-slate-400');
beforeHeader = replaceClass(beforeHeader, 'text-slate-500', 'text-slate-500 dark:text-slate-400');
beforeHeader = replaceClass(beforeHeader, 'text-indigo-600', 'text-indigo-600 dark:text-indigo-400');
beforeHeader = replaceClass(beforeHeader, 'hover:text-indigo-700', 'hover:text-indigo-700 dark:hover:text-indigo-300');

// Fix the PDF container background specifically
restOfFile = restOfFile.replace('bg-slate-50 dark:bg-slate-950 flex flex-col', 'bg-slate-50 dark:bg-slate-800/50 flex flex-col');
// Fix the inner cards background
restOfFile = restOfFile.replace(/bg-slate-50 dark:bg-slate-950 p-5/g, 'bg-slate-50 dark:bg-slate-800/50 p-5');
restOfFile = restOfFile.replace(/bg-slate-50 dark:bg-slate-950 p-6/g, 'bg-slate-50 dark:bg-slate-800/50 p-6');

fs.writeFileSync('src/App.tsx', beforeHeader + '</header>' + restOfFile);
console.log("Done");
