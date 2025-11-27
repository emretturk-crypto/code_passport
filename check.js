const fs = require('fs');
// Read the file
const rawData = fs.readFileSync('test.json', 'utf8');
const data = JSON.parse(rawData);

// Check for bad licenses
if (data.licenses.includes('AGPL-3.0')) {
  console.log('⚠️ CRITICAL RISK FOUND');
} else {
  console.log('✅ SAFE');
}