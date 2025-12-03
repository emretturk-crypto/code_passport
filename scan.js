const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs'); // Needed to read Gitleaks report
const generateCertificate = require('./generateCertificate'); 

const app = express();

// --- 1. CORS: Allow Lovable to talk to us ---
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); 
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); 
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());

// --- 2. SETUP SUPABASE ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/', (req, res) => res.send('Harmonized Audit Engine Ready'));

// --- 3. THE SCAN ENDPOINT ---
app.post('/scan', async (req, res) => {
    const { repo, token, userId } = req.body; 
    
    if (!repo) return res.status(400).send('No repo provided');

    console.log(`🚀 Request Received for: ${repo}`);

    try {
        // Create DB Record (Status: RUNNING)
        const { data: scanRecord, error: dbError } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                user_id: userId, 
                status: 'RUNNING',
                scanner_version: 'Trivy+Gitleaks', // Updated version tag
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (dbError) {
            console.error('DB Error:', dbError);
            return res.status(500).send('Database Init Failed');
        }

        const scanId = scanRecord.id;

        // Reply immediately so Frontend doesn't wait
        res.json({
            message: "Scan Started",
            scan_id: scanId,
            status: "RUNNING"
        });

        // Start the heavy work in background
        runBackgroundScan(repo, token, scanId);

    } catch (error) {
        console.error('Init Failed:', error.message);
        if (!res.headersSent) res.status(500).json({ error: error.message });
    }
});

// --- 4. THE BACKGROUND WORKER ---
async function runBackgroundScan(repo, token, scanId) {
    console.log(`⚡ Background Scan Started for ID: ${scanId}`);
    
    // Data containers
    let scanResults = {}; 
    let gitleaksResults = [];
    let status = "COMPLETED";
    let grade = 'A';
    
    try {
        // --- STEP A: AUTHENTICATION ---
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
           const cleanUrl = repo.replace('https://', '');
           authRepo = `https://${token}@${cleanUrl}`;
        }
        
        // --- STEP B: TRIVY SCAN (Vulnerabilities) ---
        console.log('🔍 Running Trivy...');
        try {
            // We scan for vulnerabilities AND config issues
            const command = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
            const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
            scanResults = JSON.parse(output);
        } catch (e) {
            console.error("Trivy Error (non-fatal):", e.message);
        }

        // --- STEP C: GITLEAKS SCAN (Secrets) ---
        // This detects AWS keys, API tokens, etc.
        console.log('🕵️‍♂️ Running Gitleaks...');
        try {
            // We assume the repo was cloned by Trivy or we clone it briefly. 
            // Since Trivy cleans up, we might need to clone specifically for Gitleaks or point Gitleaks to the repo URL.
            // Gitleaks 'detect' usually needs a local folder.
            // SIMPLIFICATION: For this MVP, we will clone to a temp folder first.
            
            const tempDir = `temp_${scanId}`;
            execSync(`git clone ${authRepo} ${tempDir}`);
            
            // Run Gitleaks on that folder
            // --no-banner: clean output
            // --exit-code=0: don't crash if leaks found
            // --report-path: save to file
            execSync(`gitleaks detect --source=./${tempDir} --report-path=${tempDir}/leaks.json --no-banner --exit-code=0`);
            
            if (fs.existsSync(`${tempDir}/leaks.json`)) {
                const leaksFile = fs.readFileSync(`${tempDir}/leaks.json`, 'utf8');
                gitleaksResults = JSON.parse(leaksFile);
            }
            
            // Cleanup temp folder
            execSync(`rm -rf ${tempDir}`);
            
        } catch (e) {
            console.error("Gitleaks Error:", e.message);
            // Try to cleanup if failed
            execSync(`rm -rf temp_${scanId}`); 
        }

        // --- STEP D: GRADING LOGIC ---
        let viralLicenses = [];
        let criticalVulns = [];
        
        // Process Trivy Results
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
                        if (vuln.Severity === 'CRITICAL') {
                            criticalVulns.push({ id: vuln.VulnerabilityID, pkg: vuln.PkgName, severity: 'CRITICAL' });
                        }
                     });
                }
            });
        }

        // Calculate Grade
        // F = Viral License OR Leaked Secrets
        // C = Critical Vulnerabilities
        // A = Clean
        if (viralLicenses.length > 0 || gitleaksResults.length > 0) {
            grade = 'F';
        } else if (criticalVulns.length > 0) {
            grade = 'C';
        }

        status = (grade === 'F') ? "FAILED" : "COMPLETED";

        // --- STEP E: PDF GENERATION ---
        console.log(`🎨 Generating PDF Certificate...`);
        const generationData = {
            grade: grade,
            viral_licenses: viralLicenses,
            critical_vulns: criticalVulns,
            leaked_secrets: gitleaksResults // Pass secrets to PDF generator
        };
        
        // NOTE: You may need to update generateCertificate.js to display secrets, 
        // but for now it will just use grade/vulns.
        const pdfBuffer = await generateCertificate(generationData, scanId, repo);
        
        // --- STEP F: UPLOAD TO SUPABASE ---
        const fileName = `${scanId}.pdf`; 
        const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;

        const { error: uploadError } = await supabase.storage
            .from('audits')
            .upload(fileName, pdfBuffer, {
                contentType: 'application/pdf',
                upsert: true 
            });

        if (uploadError) throw new Error(`Supabase Upload Failed: ${uploadError.message}`);

        const pdfUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${fileName}`;

        // --- STEP G: UPDATE DATABASE ---
        await supabase
            .from('scans')
            .update({ 
                status: status,
                risk_grade: grade,
                pdf_url: pdfUrl,
                completed_at: new Date().toISOString()
            })
            .eq('id', scanId);

        console.log(`💾 Database Updated for ${scanId} (Grade: ${grade})`);

    } catch (err) {
        console.error(`❌ Scan Failed: ${err.message}`);
        await supabase.from('scans').update({ status: 'ERROR', last_error: err.message }).eq('id', scanId);
    }
}

// --- KEEPER: PREVENT COLD STARTS ---
// Ping myself every 14 minutes to stay awake
const PING_INTERVAL = 14 * 60 * 1000; 

setInterval(() => {
    if (process.env.RENDER_EXTERNAL_URL) {
        console.log('💓 Sending Heartbeat...');
        fetch(`${process.env.RENDER_EXTERNAL_URL}/`)
            .then(res => {
                if(res.ok) console.log(`💓 Heartbeat Successful`);
            })
            .catch(err => console.error(`💔 Heartbeat Failed: ${err.message}`));
    }
}, PING_INTERVAL);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Harmonized Audit Engine running on ${PORT}`));