// VERSION 9: STABLE SENTRY V7
const Sentry = require("@sentry/node");
// Removed incompatible profiling import

// 1. Initialize Sentry (V7 Compatible)
Sentry.init({
  dsn: "https://34b8ed55cbf2419c2fdabe9683ff8366@o4510486964928512.ingest.de.sentry.io/4510487797760080",
  // We removed the 'integrations' block that was causing the crash
  tracesSampleRate: 1.0, 
});

const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs'); 
const generateCertificate = require('./generateCertificate'); 
const fetch = require('node-fetch'); 
const { run, quickAddJob } = require("graphile-worker"); 

const app = express();

// Sentry Request Handler (V7 Compatible)
app.use(Sentry.Handlers.requestHandler());

// --- 2. CORS ---
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); 
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); 
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());

// --- 3. CONFIG ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const connectionString = process.env.DATABASE_URL; 

// --- 4. THE WORKER TASK ---
const taskList = {
    scan_repo: async (payload, helpers) => {
        const { repo, token, scanId, userId } = payload;
        console.log(`👷 WORKER: Processing Scan ID ${scanId}`);

        let scanResults = {}; 
        let gitleaksResults = [];
        let grade = 'A';
        let sbomUrl = null; 
        
        try {
            const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;
            let authRepo = repo;
            if (token && repo.includes('github.com')) {
               const cleanUrl = repo.replace('https://', '');
               authRepo = `https://${token}@${cleanUrl}`;
            }
            
            // A. TRIVY (Security Scan)
            console.log('   🔍 Running Trivy (Security)...');
            try {
                const output = execSync(`trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
                scanResults = JSON.parse(output);
            } catch (e) { 
                console.log("   Trivy warning:", e.message); 
            }

            // A2. SBOM GENERATION
            console.log('   📦 Generating SBOM (Inventory)...');
            const sbomPath = `sbom_${scanId}.json`;
            try {
                execSync(`trivy repo ${authRepo} --format cyclonedx --output ${sbomPath} --quiet`);
                
                if (fs.existsSync(sbomPath)) {
                    const sbomBuffer = fs.readFileSync(sbomPath);
                    await supabase.storage
                        .from('audits')
                        .upload(sbomPath, sbomBuffer, { contentType: 'application/json', upsert: true });
                        
                    sbomUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${sbomPath}`;
                    fs.unlinkSync(sbomPath);
                }
            } catch (e) {
                console.log("   ⚠️ SBOM Generation failed:", e.message);
                Sentry.captureException(e); 
            }

            // B. GITLEAKS (Secrets)
            console.log('   🕵️‍♂️ Running Gitleaks...');
            const tempDir = `temp_${scanId}`;
            try {
                execSync(`git clone --depth 1 ${authRepo} ${tempDir}`);
                execSync(`gitleaks detect --source=./${tempDir} --report-path=${tempDir}/leaks.json --no-banner --exit-code=0`);
                
                if (fs.existsSync(`${tempDir}/leaks.json`)) {
                    const file = fs.readFileSync(`${tempDir}/leaks.json`, 'utf8');
                    gitleaksResults = JSON.parse(file);
                    console.log(`   ⚠️ Found ${gitleaksResults.length} secrets.`);
                }
                execSync(`rm -rf ${tempDir}`);
            } catch (e) {
                console.error("   Gitleaks Error:", e.message);
                Sentry.captureException(e);
                execSync(`rm -rf ${tempDir}`);
            }

            // C. GRADING
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

            // D. PDF GENERATION
            console.log("   🎨 Generating PDF...");
            const generationData = { grade, viral_licenses: viralLicenses, critical_vulns: criticalVulns, leaked_secrets: gitleaksResults };
            const pdfBuffer = await generateCertificate(generationData, scanId, repo);
            
            const fileName = `${scanId}.pdf`;

            await supabase.storage.from('audits').upload(fileName, pdfBuffer, { contentType: 'application/pdf', upsert: true });
            
            const pdfUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${fileName}`;

            // E. FINAL DB UPDATE
            await supabase.from('scans').update({ 
                status: "COMPLETED", 
                risk_grade: grade,    
                pdf_url: pdfUrl,
                sbom_url: sbomUrl,
                completed_at: new Date().toISOString()
            }).eq('id', scanId);

            console.log(`   ✅ Scan ${scanId} Finished (Grade: ${grade})`);

        } catch (err) {
            console.error(`   ❌ Worker Failed: ${err.message}`);
            Sentry.captureException(err);
            await supabase.from('scans').update({ status: 'ERROR', last_error: err.message }).eq('id', scanId);
            throw err; 
        }
    }
};

// --- 5. START QUEUE LISTENER ---
async function startWorker() {
    if (!connectionString) {
        console.error("❌ MISSING DATABASE_URL! Worker cannot start.");
        return;
    }
    console.log("🚜 Starting Job Worker...");
    await run({
        connectionString,
        concurrency: 2, 
        pollInterval: 1000,
        taskList,
    });
}

// --- 6. API ENDPOINT ---
app.post('/scan', async (req, res) => {
    const { repo, token, userId } = req.body; 
    
    if (!repo) return res.status(400).send('No repo provided');
    console.log(`🚀 Request Queued for: ${repo}`);

    try {
        const { data: scanRecord, error } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                user_id: userId, 
                status: 'QUEUED', 
                scanner_version: 'v9-StableSentry', 
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (error) return res.status(500).send('Database Error');

        if (connectionString) {
            await quickAddJob(
                { connectionString }, 
                "scan_repo", 
                { repo, token, scanId: scanRecord.id, userId }
            );
            res.json({ message: "Scan Queued", scan_id: scanRecord.id, status: "QUEUED" });
        } else {
            const err = new Error("Server missing DATABASE_URL");
            Sentry.captureException(err);
            res.status(500).json({ error: "Server missing DATABASE_URL" });
        }

    } catch (error) {
        console.error('Init Failed:', error.message);
        Sentry.captureException(error);
        res.status(500).json({ error: error.message });
    }
});

// Sentry Error Handler (V7 Compatible)
app.use(Sentry.Handlers.errorHandler());

// Heartbeat
setInterval(() => {
    if (process.env.RENDER_EXTERNAL_URL) fetch(`${process.env.RENDER_EXTERNAL_URL}/`).catch(()=>{});
}, 14 * 60 * 1000);

// Start Server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Receptionist running on ${PORT}`);
    startWorker().catch(e => {
        console.error("Worker failed to start:", e);
        Sentry.captureException(e);
    });
});