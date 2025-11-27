const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.use(express.json());

// Add a Health Check endpoint so Render knows we are alive
app.get('/', (req, res) => {
    res.send('Scanner is Ready');
});

app.post('/scan', (req, res) => {
    const { repo } = req.body;
    
    if (!repo) return res.status(400).send('No repo provided');

    console.log(`🚀 Scanning: ${repo}`);

    try {
        // Run Trivy Scan
        // We use --timeout 30m to handle large repos
        const command = `trivy repo ${repo} --scanners license,vuln --format json --timeout 30m`;
        const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
        
        // Return the raw JSON to Make.com
        res.json(JSON.parse(output));
        
    } catch (error) {
        console.error('Scan Error:', error.message);
        // We still send the error back so Make.com knows it failed
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Scanner listening on port ${PORT}`));