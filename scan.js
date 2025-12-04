// VERSION 6: QUEUE-BASED ARCHITECTURE
const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs'); 
const generateCertificate = require('./generateCertificate'); 
const fetch = require('node-fetch'); 
const { run, quickAddJob } = require("graphile-worker"); // The Queue Library

const app = express();

// --- 1. CORS ---
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); 
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); 
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());

// --- 2. CONFIG ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
// The connection string you just saved in Render
const connectionString = process.env.DATABASE_URL; 

// --- 3. THE WORKER TASK (This runs in the background) ---
const taskList = {
    scan_repo: async (payload, helpers) => {
        const { repo, token, scanId, userId } = payload;
        console.log(`👷 WORKER: Processing Scan ID ${scanId}`);

        // --- SCANNING LOGIC MOVED HERE ---
        let scanResults = {}; 
        let gitleaksResults = [];
        let grade = 'A';
        
        try {
            let authRepo = repo;
            if (token && repo.includes('github.com')) {
               const cleanUrl = repo.replace('https://', '');
               authRepo = `https://${token}@${cleanUrl}`;
            }
            
            // A. TRIVY
            console.log('   🔍 Running Trivy...');
            try {
                const output = execSync(`trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
                scanResults = JSON.parse(output);
            } catch (e) { console.log("   Trivy warning:", e.message); }

            // B. GITLEAKS
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

            // D. PDF & DB
            console.log("   🎨 Generating PDF...");
            const generationData = { grade, viral_licenses: viralLicenses, critical_vulns: criticalVulns, leaked_secrets: gitleaksResults };
            const pdfBuffer = await generateCertificate(generationData, scanId, repo);
            
            const fileName = `${scanId}.pdf`;
            const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;

            await supabase.storage.from('audits').upload(fileName, pdfBuffer, { contentType: 'application/pdf', upsert: true });
            
            const pdfUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${fileName}`;

            // Final Update: Mark as COMPLETED
            await supabase.from('scans').update({ 
                status: "COMPLETED", 
                risk_grade: grade,    
                pdf_url: pdfUrl,
                completed_at: new Date().toISOString()
            }).eq('id', scanId);

            console.log(`   ✅ Scan ${scanId} Finished (Grade: ${grade})`);

        } catch (err) {
            console.error(`   ❌ Worker Failed: ${err.message}`);
            await supabase.from('scans').update({ status: 'ERROR', last_error: err.message }).eq('id', scanId);
            // Throwing error makes the Queue retry automatically later!
            throw err; 
        }
    }
};

// --- 4. START QUEUE LISTENER ---
async function startWorker() {
    if (!connectionString) {
        console.error("❌ MISSING DATABASE_URL! Worker cannot start.");
        return;
    }
    console.log("🚜 Starting Job Worker...");
    // This function runs alongside the web server
    await run({
        connectionString,
        concurrency: 2, // Safety Limit: Only 2 scans at once to prevent crashes
        pollInterval: 1000,
        taskList,
    });
}

// --- 5. API ENDPOINT (The Receptionist) ---
app.post('/scan', async (req, res) => {
    const { repo, token, userId } = req.body; 
    
    if (!repo) return res.status(400).send('No repo provided');
    console.log(`🚀 Request Queued for: ${repo}`);

    try {
        // 1. Create "QUEUED" Record
        const { data: scanRecord, error } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                user_id: userId, 
                status: 'QUEUED', // New Status!
                scanner_version: 'v6-Queue',
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (error) return res.status(500).send('Database Error');

        // 2. Add to Job Queue (Instant)
        // This takes 10ms, instead of waiting for the scan
        if (connectionString) {
            await quickAddJob(
                { connectionString }, 
                "scan_repo", 
                { repo, token, scanId: scanRecord.id, userId }
            );
            res.json({ message: "Scan Queued", scan_id: scanRecord.id, status: "QUEUED" });
        } else {
            res.status(500).json({ error: "Server missing DATABASE_URL" });
        }

    } catch (error) {
        console.error('Init Failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Heartbeat
setInterval(() => {
    if (process.env.RENDER_EXTERNAL_URL) fetch(`${process.env.RENDER_EXTERNAL_URL}/`).catch(()=>{});
}, 14 * 60 * 1000);

// Start Server AND Worker
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Receptionist running on ${PORT}`);
    startWorker().catch(e => console.error("Worker failed to start:", e));
});