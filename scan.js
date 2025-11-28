const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const app = express();

app.use(express.json());

// Initialize Database Connection
// We use 'process.env' so we don't hardcode secrets in the code
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/', (req, res) => res.send('Audit Engine Ready'));

app.post('/scan', async (req, res) => {
    const { repo, token } = req.body;
    if (!repo) return res.status(400).send('No repo provided');

    console.log(`🚀 Starting Audit for: ${repo}`);

    try {
        // 1. Create the "Queued" Record in DB
        // We assume a default Organization ID for now (you can update this logic later)
        // This creates the "Paper Trail" before we even start
        const { data: scanRecord, error: dbError } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                status: 'RUNNING',
                scanner_version: 'Trivy v0.48.3' 
            }])
            .select()
            .single();

        if (dbError) console.error('DB Error:', dbError);
        const scanId = scanRecord ? scanRecord.id : null;

        // 2. Prepare Authentication
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
            const cleanUrl = repo.replace('https://', '');
            authRepo = `https://${token}@${cleanUrl}`;
        }

        // 3. Run the Scan
        const command = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
        const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
        const json = JSON.parse(output);

        // 4. Analyze Risks
        let viralLicenses = [];
        let criticalVulns = [];
        
        if (json.Results) {
            json.Results.forEach(target => {
                if (target.Licenses) {
                    target.Licenses.forEach(lic => {
                        if (['AGPL', 'GPL', 'SSPL'].some(bad => lic.Name.includes(bad))) {
                            viralLicenses.push({ pkg: lic.PkgName, license: lic.Name });
                        }
                    });
                }
                if (target.Vulnerabilities) {
                    target.Vulnerabilities.forEach(vuln => {
                        if (vuln.Severity === 'CRITICAL') {
                            criticalVulns.push({ id: vuln.VulnerabilityID, pkg: vuln.PkgName });
                        }
                    });
                }
            });
        }

        // 5. Calculate Risk Grade (Bank Requirement)
        let grade = 'A';
        if (viralLicenses.length > 0) grade = 'F';
        else if (criticalVulns.length > 0) grade = 'C';

        const status = (grade === 'F') ? "FAILED" : "COMPLETED";

        // 6. Save Final Results to DB
        if (scanId) {
            await supabase
                .from('scans')
                .update({ 
                    status: status,
                    risk_grade: grade,
                    findings_json: json,
                    completed_at: new Date().toISOString()
                })
                .eq('id', scanId);
        }

        // 7. Send Response to Make.com
        // We send the HTML summary so the PDF generator works
        const licenseTable = viralLicenses.length > 0 
            ? viralLicenses.map(l => `<li style="color:red;">🔴 <strong>${l.pkg}</strong> (${l.license})</li>`).join('')
            : "<li>✅ No Viral Licenses Found</li>";

        const vulnTable = criticalVulns.length > 0
            ? criticalVulns.slice(0, 5).map(v => `<li>⚠️ <strong>${v.pkg}</strong>: ${v.id}</li>`).join('')
            : "<li>✅ No Critical Vulnerabilities</li>";

        res.json({
            scan_id: scanId,
            repo_name: repo,
            scan_date: new Date().toISOString(),
            risk_grade: grade,
            status: status,
            html_licenses: `<ul>${licenseTable}</ul>`,
            html_vulns: `<ul>${vulnTable}</ul>`
        });
        
    } catch (error) {
        console.error('Audit Failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Audit Engine running on ${PORT}`));