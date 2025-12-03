// VERSION 4: FINAL PRODUCTION ENGINE - Self-Healing & Stable
const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs'); 
const generateCertificate = require('./generateCertificate'); 
const fetch = require('node-fetch'); // Required for Heartbeat

const app = express();

// --- 1. CORS & CONFIG ---
// Allows the Lovable frontend to communicate with this server
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

// --- 3. SELF-HEALING INSTALLER (Gitleaks) ---
// Guarantees the secret scanner is present, even if Docker or Render's setup fails.
function ensureGitleaks() {
    if (fs.existsSync('./gitleaks')) {
        return; 
    }
    
    console.log("🛠️ Gitleaks binary missing. Auto-installing now...");
    try {
        // Download Linux binary
        execSync('wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz');
        // Extract
        execSync('tar -xzf gitleaks_8.18.2_linux_x64.tar.gz');
        // Make executable
        execSync('chmod +x gitleaks');
        console.log("✅ Gitleaks installed successfully via Auto-Fix.");
    } catch (e) {
        console.error("❌ Critical: Failed to auto-install Gitleaks:", e.message);
    }
}

app.get('/', (req, res) => res.send('Harmonized Audit Engine Ready (v4)'));

// --- 4. THE SCAN ENDPOINT ---
app.post('/scan', async (req, res) => {
    const { repo, token, userId } = req.body; 
    
    // Run the auto-fixer before every scan
    ensureGitleaks();

    if (!repo) return res.status(400).send('No repo provided');
    console.log(`🚀 Request Received for: ${repo}`);

    try {
        // Create DB Record
        const { data: scanRecord, error: dbError } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                user_id: userId, // CRITICAL: Links the scan to the user's session
                status: 'RUNNING',
                scanner_version: 'v4-Final',
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (dbError) {
            console.error('DB Error:', dbError);
            // This is likely the Schema Cache issue we saw earlier
            return res.status(500).send('Database Init Failed (Check Supabase Cache)');
        }

        const scanId = scanRecord.id;

        // Reply immediately
        res.json({
            message: "Scan Started",
            scan_id: scanId,
            status: "RUNNING"
        });

        // Start background work
        runBackgroundScan(repo, token, scanId);

    } catch (error) {
        console.error('Init Failed:', error.message);
        if (!res.headersSent) res.status(500).json({ error: error.message });
    }
});

// --- 5. THE WORKER ---
async function runBackgroundScan(repo, token, scanId) {
    console.log(`⚡ Background Scan Started for ID: ${scanId}`);
    
    let scanResults = {}; 
    let gitleaksResults = [];
    let grade = 'A';
    
    try {
        // --- Setup Auth ---
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
           const cleanUrl = repo.replace('https://', '');
           authRepo = `https://${token}@${cleanUrl}`;
        }
        
        // --- A. TRIVY SCAN (Vulnerabilities/Licenses) ---
        console.log('🔍 Running Trivy...');
        try {
            const command = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
            const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
            scanResults = JSON.parse(output);
        } catch (e) {
            console.error("Trivy Error (non-fatal):", e.message);
        }

        // --- B. GITLEAKS SCAN (Secrets) ---
        console.log('🕵️‍♂️ Running Gitleaks...');
        const tempDir = `temp_${scanId}`;
        try {
            execSync(`git clone ${authRepo} ${tempDir}`);
            
            // Running the locally installed binary
            execSync(`./gitleaks detect --source=./${tempDir} --report-path=${tempDir}/leaks.json --no-banner --exit-code=0`);
            
            if (fs.existsSync(`${tempDir}/leaks.json`)) {
                const leaksFile = fs.readFileSync(`${tempDir}/leaks.json`, 'utf8');
                gitleaksResults = JSON.parse(leaksFile);
                console.log(`   ⚠️ Gitleaks found ${gitleaksResults.length} secrets!`);
            }
            
            execSync(`rm -rf ${tempDir}`);
        } catch (e) {
            console.error("❌ Gitleaks Logic Error:", e.message);
            execSync(`rm -rf ${tempDir}`); 
        }

        // --- C. GRADING LOGIC ---
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
                        if (vuln.Severity === 'CRITICAL') {
                            criticalVulns.push({ id: vuln.VulnerabilityID, pkg: vuln.PkgName, severity: 'CRITICAL' });
                        }
                     });
                }
            });
        }

        // Strict Grading Rule: F for Secrets or Viral Licenses. C for Critical Vulns.
        if (viralLicenses.length > 0 || gitleaksResults.length > 0) {
            grade = 'F'; 
        } else if (criticalVulns.length > 0) {
            grade = 'C';
        }

        // --- D. PDF GENERATION & DB UPDATE ---
        console.log(`🎨 Generating PDF...`);
        const generationData = {
            grade: grade,
            viral_licenses: viralLicenses,
            critical_vulns: criticalVulns,
            leaked_secrets: gitleaksResults 
        };
        
        const pdfBuffer = await generateCertificate(generationData, scanId, repo);
        
        const fileName = `${scanId}.pdf`; 
        const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;

        await supabase.storage.from('audits').upload(fileName, pdfBuffer, {
            contentType: 'application/pdf', upsert: true 
        });

        const pdfUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${fileName}`;

        // UX FIX: Set status to COMPLETED even if the grade is F. The grade is the result.
        await supabase
            .from('scans')
            .update({ 
                status: "COMPLETED", // System completed the task successfully
                risk_grade: grade,    // Result of the audit is F/C/A
                pdf_url: pdfUrl,
                completed_at: new Date().toISOString()
            })
            .eq('id', scanId);

        console.log(`💾 Database Updated for ${scanId} (Final Grade: ${grade})`);

    } catch (err) {
        console.error(`❌ Scan Failed: ${err.message}`);
        // Only mark as ERROR status if the system itself crashed
        await supabase.from('scans').update({ status: 'ERROR', last_error: err.message }).eq('id', scanId);
    }
}

// --- 6. HEARTBEAT (Keep Alive) ---
const PING_INTERVAL = 14 * 60 * 1000; 
setInterval(() => {
    if (process.env.RENDER_EXTERNAL_URL) {
        // Use fetch from node-fetch
        fetch(`${process.env.RENDER_EXTERNAL_URL}/`).catch(e => {});
    }
}, PING_INTERVAL);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Harmonized Audit Engine running on ${PORT}`));