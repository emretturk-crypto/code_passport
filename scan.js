// Force Update v2 - Self Healing Engine
const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs'); 
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

// --- 3. SELF-INSTALLER FUNCTION (The Fix) ---
// If Docker failed to install Gitleaks, this script does it manually.
function ensureGitleaks() {
    if (fs.existsSync('./gitleaks')) {
        return; // Already installed
    }
    
    console.log("🛠️ Gitleaks binary missing. Auto-installing now...");
    try {
        // 1. Download the Linux binary
        execSync('wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz');
        // 2. Unzip it
        execSync('tar -xzf gitleaks_8.18.2_linux_x64.tar.gz');
        // 3. Make it executable
        execSync('chmod +x gitleaks');
        console.log("✅ Gitleaks installed successfully via Auto-Fix.");
    } catch (e) {
        console.error("❌ Critical: Failed to auto-install Gitleaks:", e.message);
    }
}

app.get('/', (req, res) => res.send('Harmonized Audit Engine Ready'));

// --- 4. THE SCAN ENDPOINT ---
app.post('/scan', async (req, res) => {
    const { repo, token, userId } = req.body; 
    
    // Run the auto-fixer before every scan to ensure tools exist
    ensureGitleaks();

    if (!repo) return res.status(400).send('No repo provided');
    console.log(`🚀 Request Received for: ${repo}`);

    try {
        // Create DB Record
        const { data: scanRecord, error: dbError } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                user_id: userId, 
                status: 'RUNNING',
                scanner_version: 'Trivy+Gitleaks',
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (dbError) {
            console.error('DB Error:', dbError);
            return res.status(500).send('Database Init Failed');
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
    let status = "COMPLETED";
    let grade = 'A';
    
    try {
        // Auth Logic
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
           const cleanUrl = repo.replace('https://', '');
           authRepo = `https://${token}@${cleanUrl}`;
        }
        
        // A. TRIVY SCAN
        console.log('🔍 Running Trivy...');
        try {
            const command = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
            const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
            scanResults = JSON.parse(output);
        } catch (e) {
            console.error("Trivy Error (non-fatal):", e.message);
        }

        // B. GITLEAKS SCAN (Robust Version)
        console.log('🕵️‍♂️ Running Gitleaks...');
        const tempDir = `temp_${scanId}`;
        try {
            // 1. Clone
            console.log(`   Cloning to ${tempDir}...`);
            execSync(`git clone ${authRepo} ${tempDir}`);
            
            // 2. Verify files exist (Debug Log)
            const fileList = execSync(`ls -R ${tempDir}`).toString();
            console.log(`   Files found (snippet): ${fileList.substring(0, 100)}...`);

            // 3. Run the local binary (./gitleaks)
            console.log('   Scanning files...');
            execSync(`./gitleaks detect --source=./${tempDir} --report-path=${tempDir}/leaks.json --no-banner --exit-code=0 --verbose`);
            
            // 4. Read results
            if (fs.existsSync(`${tempDir}/leaks.json`)) {
                const leaksFile = fs.readFileSync(`${tempDir}/leaks.json`, 'utf8');
                gitleaksResults = JSON.parse(leaksFile);
                console.log(`   ⚠️ Gitleaks found ${gitleaksResults.length} secrets!`);
            } else {
                console.log(`   ✅ Gitleaks found 0 secrets.`);
            }
            
            // Cleanup
            execSync(`rm -rf ${tempDir}`);
            
        } catch (e) {
            console.error("❌ Gitleaks Logic Error:", e.message);
            execSync(`rm -rf ${tempDir}`); 
        }

        // C. GRADING LOGIC
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

        // The Strict Grading Rule: Secrets = Automatic F
        if (viralLicenses.length > 0 || gitleaksResults.length > 0) {
            grade = 'F'; 
        } else if (criticalVulns.length > 0) {
            grade = 'C';
        }

        status = (grade === 'F') ? "FAILED" : "COMPLETED";

        // D. PDF GENERATION
        console.log(`🎨 Generating PDF...`);
        const generationData = {
            grade: grade,
            viral_licenses: viralLicenses,
            critical_vulns: criticalVulns,
            leaked_secrets: gitleaksResults 
        };
        
        const pdfBuffer = await generateCertificate(generationData, scanId, repo);
        
        // E. UPLOAD
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

        // F. DB UPDATE
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

// --- 6. HEARTBEAT (Keep Alive) ---
const PING_INTERVAL = 14 * 60 * 1000; 
setInterval(() => {
    if (process.env.RENDER_EXTERNAL_URL) {
        console.log('💓 Sending Heartbeat...');
        fetch(`${process.env.RENDER_EXTERNAL_URL}/`).catch(e => {});
    }
}, PING_INTERVAL);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Harmonized Audit Engine running on ${PORT}`));