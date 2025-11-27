const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.use(express.json());

// Health Check
app.get('/', (req, res) => {
    res.send('Scanner is Ready');
});

// The Main Scan Route
app.post('/scan', (req, res) => {
    const { repo } = req.body;
    
    if (!repo) return res.status(400).send('No repo provided');

    console.log(`🚀 Scanning: ${repo}`);

    try {
        // Run Trivy with --quiet flag to stop it from printing "Downloading..." text
        // This ensures the output is pure JSON
        const command = `trivy repo ${repo} --scanners license,vuln --format json --timeout 30m --quiet`;
        
        console.log('⏳ Running Trivy (This takes time)...');
        
        // Execute command
        const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
        
        // Parse and send back to Make.com
        res.json(JSON.parse(output));
        console.log('✅ Scan Complete');
        
    } catch (error) {
        console.error('❌ Scan Failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Scanner listening on port ${PORT}`));