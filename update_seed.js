const fs = require('fs');
let code = fs.readFileSync('prisma/seed.ts', 'utf8');

code = code.replace(/apps\['[^']+'\] = await prisma\.application\.upsert\(\{\s*where: \{ appId: '[^']+' \},\s*update: \{\},\s*create: (\{[\s\S]*?\n    \}),\s*\}\);/g, (match, createBlock) => {
  return match.replace('update: {},', 'update: ' + createBlock + ',');
});

fs.writeFileSync('prisma/seed.ts', code);
console.log("Updated seed.ts");
