const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const app = express();

app.use(express.json());

app.post('/scan', (req, res) => {
    const { repo } = req.body;
    
    if (!repo) return res.status(400).send('No repo provided');

    console.log(`🚀 Scanning: ${repo}`);

    try {
        // Run Trivy Scan
        const command = `trivy repo ${repo} --scanners license,vuln --format json`;
        const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
        
        // Return the raw JSON to Make.com
        res.json(JSON.parse(output));
        
    } catch (error) {
        console.error(error);
        res.status(500).send('Scan failed');
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Scanner listening on port ${PORT}`));}