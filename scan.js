const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs'); 
const generateCertificate = require('./generateCertificate'); 

const app = express();

// 1. Allow Frontend Access (CORS)
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); 
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); 
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());

// 2. Setup Database
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/', (req, res) => res.send('Audit Engine Online'));

// 3. Scan Endpoint
app.post('/scan', async (req, res) => {
    const { repo, token, userId } = req.body; 
    
    if (!repo) return res.status(400).send('No repo provided');
    console.log(`🚀 Starting scan for: ${repo}`);

    // Create "RUNNING" record
    const { data: scanRecord, error } = await supabase
        .from('scans')
        .insert([{ 
            repo_url: repo, 
            user_id: userId,
            status: 'RUNNING',
            created_at: new Date().toISOString()
        }])
        .select()
        .single();

    if (error) {
        console.error('DB Error:', error);
        return res.status(500).send('Database Error');
    }

    // Reply immediately
    res.json({ message: "Scan Started", scan_id: scanRecord.id, status: "RUNNING" });

    // Run scan in background
    runScan(repo, token, scanRecord.id);
});

async function runScan(repo, token, scanId) {
    let grade = 'A';
    let scanResults = {};
    let gitleaksResults = [];

    try {
        // Prepare Auth URL
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
           const cleanUrl = repo.replace('https://', '');
           authRepo = `https://${token}@${cleanUrl}`;
        }

        // A. Run Trivy
        console.log('🔍 Running Trivy...');
        try {
            const cmd = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
            const output = execSync(cmd, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
            scanResults = JSON.parse(output);
        } catch (e) { console.log("Trivy warning:", e.message); }

        // B. Run Gitleaks
        console.log('🕵️‍♂️ Running Gitleaks...');
        const tempDir = `temp_${scanId}`;
        try {
            execSync(`git clone ${authRepo} ${tempDir}`);
            // Run the installed tool
            execSync(`gitleaks detect --source=./${tempDir} --report-path=${tempDir}/leaks.json --no-banner --exit-code=0`);
            
            if (fs.existsSync(`${tempDir}/leaks.json`)) {
                const file = fs.readFileSync(`${tempDir}/leaks.json`, 'utf8');
                gitleaksResults = JSON.parse(file);
            }
            execSync(`rm -rf ${tempDir}`);
        } catch (e) { 
            console.log("Gitleaks warning:", e.message);
            execSync(`rm -rf ${tempDir}`);
        }

        // C. Calculate Grade
        let viralLicenses = [];
        let criticalVulns = [];

        if (scanResults.Results) {
            scanResults.Results.forEach(target => {
                if (target.Licenses) {
                    target.Licenses.forEach(lic => {
                        if (['AGPL', 'GPL', 'SSPL'].some(bad => lic.Name.includes(bad))) {
                            viralLicenses.push({ pkg: lic.PkgName, license: lic.Name });
                        }
                    });
                }
                if (target.Vulnerabilities) {
                     target.Vulnerabilities.forEach(vuln => {
                        if (vuln.Severity === 'CRITICAL') criticalVulns.push(vuln);
                     });
                }
            });
        }

        if (viralLicenses.length > 0 || gitleaksResults.length > 0) grade = 'F';
        else if (criticalVulns.length > 0) grade = 'C';

        // D. Generate PDF & Upload
        console.log('🎨 Generating PDF...');
        const pdfBuffer = await generateCertificate({
            grade, viral_licenses: viralLicenses, critical_vulns: criticalVulns, leaked_secrets: gitleaksResults
        }, scanId, repo);

        const fileName = `${scanId}.pdf`;
        // Handle URL slash issues
        const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;
        
        await supabase.storage.from('audits').upload(fileName, pdfBuffer, {
            contentType: 'application/pdf', upsert: true 
        });

        const pdfUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${fileName}`;

        // E. Update DB
        await supabase.from('scans').update({ 
            status: 'COMPLETED',
            risk_grade: grade,
            pdf_url: pdfUrl,
            completed_at: new Date().toISOString()
        }).eq('id', scanId);

        console.log(`✅ Scan Finished: Grade ${grade}`);

    } catch (err) {
        console.error(`❌ Fatal Error: ${err.message}`);
        await supabase.from('scans').update({ status: 'ERROR' }).eq('id', scanId);
    }
}

// Heartbeat to keep server awake
setInterval(() => {
    if (process.env.RENDER_EXTERNAL_URL) {
        // Simple fetch without extra dependency
        const https = require('https');
        https.get(process.env.RENDER_EXTERNAL_URL);
    }
}, 14 * 60 * 1000);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Engine running on ${PORT}`));