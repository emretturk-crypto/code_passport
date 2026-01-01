// VERSION 11: ASYNC ENGINE + SECURITY HARDENING + SENTRY V7
const Sentry = require("@sentry/node");

// 1. Initialize Sentry
Sentry.init({
  dsn: "https://34b8ed55cbf2419c2fdabe9683ff8366@o4510486964928512.ingest.de.sentry.io/4510487797760080",
  tracesSampleRate: 1.0, 
});

const express = require('express');
const { spawn } = require('child_process'); // <--- CHANGED: Using spawn instead of execSync
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs'); 
const generateCertificate = require('./generateCertificate'); 
const fetch = require('node-fetch'); 
const { run, quickAddJob } = require("graphile-worker"); 

const app = express();

// Sentry Request Handler
app.use(Sentry.Handlers.requestHandler());

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); 
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); 
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());

// CONFIG
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const connectionString = process.env.DATABASE_URL; 

// --- 🛡️ SECURE COMMAND RUNNER (The New Engine Heart) ---
// 1. Returns a Promise (Non-blocking)
// 2. Uses argument arrays (Prevents Command Injection)
function runCommand(command, args, cwd = null) {
    return new Promise((resolve, reject) => {
        // shell: false is crucial. It means "don't use terminal", just run the file.
        // This makes "rm -rf /" impossible to inject.
        const proc = spawn(command, args, { cwd, shell: false });
        
        let stdout = '';
        let stderr = '';

        // Capture output efficiently
        proc.stdout.on('data', (data) => { stdout += data; });
        proc.stderr.on('data', (data) => { stderr += data; });

        proc.on('close', (code) => {
            if (code === 0) {
                resolve(stdout.trim());
            } else {
                // Reject with the error output so we know what broke
                reject(new Error(`Command failed: ${command} ${args.join(' ')}\nStderr: ${stderr}`));
            }
        });
        
        proc.on('error', (err) => reject(err));
    });
}

// --- THE WORKER TASK ---
const taskList = {
    scan_repo: async (payload, helpers) => {
        const { repo, token, scanId, userId } = payload;
        console.log(`👷 WORKER: Processing Scan ID ${scanId}`);

        let scanResults = {}; 
        let gitleaksResults = [];
        let grade = 'A';
        let sbomUrl = null; 
        let currentHash = null;
        
        try {
            const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;
            
            // 1. Construct Auth URL (Securely)
            // Note: We will pass the token via environment vars or secure args in Phase 3.
            // For now, we construct the URL but will run it safely.
            let authRepo = repo;
            if (token && repo.includes('github.com')) {
               const cleanUrl = repo.replace('https://', '');
               authRepo = `https://${token}@${cleanUrl}`;
            }

            // ---------------------------------------------------------
            // 🛑 CACHE CHECK (Async Version)
            // ---------------------------------------------------------
            console.log('   🔎 Checking Commit Hash...');
            try {
                // New: spawn('git', ['ls-remote', ...])
                const hashOutput = await runCommand('git', ['ls-remote', authRepo, 'HEAD']);
                currentHash = hashOutput.split('\t')[0];
                console.log(`   🎯 Commit Hash: ${currentHash}`);

                const { data: cachedScan } = await supabase
                    .from('scans')
                    .select('*')
                    .eq('repo_url', repo)
                    .eq('commit_hash', currentHash)
                    .eq('status', 'COMPLETED')
                    .limit(1)
                    .maybeSingle();

                if (cachedScan) {
                    console.log(`   ⚡ CACHE HIT! Using results from Scan ${cachedScan.id}`);
                    await supabase.from('scans').update({ 
                        status: "COMPLETED", 
                        risk_grade: cachedScan.risk_grade,    
                        pdf_url: cachedScan.pdf_url,
                        sbom_url: cachedScan.sbom_url,
                        commit_hash: currentHash,
                        last_error: "Cached Result",
                        completed_at: new Date().toISOString()
                    }).eq('id', scanId);
                    return; 
                }
            } catch (e) {
                console.log("   ⚠️ Cache check warning:", e.message);
                // Don't crash, just proceed
            }
            // ---------------------------------------------------------
            
            // A. TRIVY (Security Scan)
            console.log('   🔍 Running Trivy (Security)...');
            try {
                // Async + Array Args
                const output = await runCommand('trivy', [
                    'repo', 
                    authRepo, 
                    '--scanners', 'license,vuln', 
                    '--format', 'json', 
                    '--timeout', '30m', 
                    '--quiet'
                ]);
                scanResults = JSON.parse(output);
            } catch (e) { console.log("   Trivy warning:", e.message); }

            // A2. SBOM GENERATION
            console.log('   📦 Generating SBOM...');
            const sbomPath = `sbom_${scanId}.json`;
            try {
                await runCommand('trivy', [
                    'repo', 
                    authRepo, 
                    '--format', 'cyclonedx', 
                    '--output', sbomPath, 
                    '--quiet'
                ]);
                
                if (fs.existsSync(sbomPath)) {
                    const sbomBuffer = fs.readFileSync(sbomPath);
                    await supabase.storage.from('audits').upload(sbomPath, sbomBuffer, { contentType: 'application/json', upsert: true });
                    sbomUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${sbomPath}`;
                    fs.unlinkSync(sbomPath);
                }
            } catch (e) { console.log("   ⚠️ SBOM failed:", e.message); }

            // B. GITLEAKS (Secrets)
            console.log('   🕵️‍♂️ Running Gitleaks...');
            const tempDir = `temp_${scanId}`;
            try {
                // 1. Clone securely
                await runCommand('git', ['clone', '--depth', '1', authRepo, tempDir]);
                
                // 2. Detect Secrets
                await runCommand('gitleaks', [
                    'detect', 
                    `--source=./${tempDir}`, 
                    `--report-path=${tempDir}/leaks.json`, 
                    '--no-banner', 
                    '--exit-code=0'
                ]);
                
                if (fs.existsSync(`${tempDir}/leaks.json`)) {
                    const file = fs.readFileSync(`${tempDir}/leaks.json`, 'utf8');
                    gitleaksResults = JSON.parse(file);
                    console.log(`   ⚠️ Found ${gitleaksResults.length} secrets.`);
                }
                // Cleanup
                await runCommand('rm', ['-rf', tempDir]);
            } catch (e) {
                console.error("   Gitleaks Error:", e.message);
                // Ensure cleanup happens even on error
                try { await runCommand('rm', ['-rf', tempDir]); } catch(err){} 
            }

            // C. GRADING (Same Logic)
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

            // E. FINAL UPDATE
            await supabase.from('scans').update({ 
                status: "COMPLETED", 
                risk_grade: grade,    
                pdf_url: pdfUrl,
                sbom_url: sbomUrl,
                commit_hash: currentHash,
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

async function startWorker() {
    if (!connectionString) { console.error("❌ MISSING DATABASE_URL!"); return; }
    console.log("🚜 Starting Job Worker...");
    await run({ connectionString, concurrency: 2, pollInterval: 1000, taskList });
}

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
                scanner_version: 'v11-AsyncEngine', 
                created_at: new Date().toISOString() 
            }])
            .select().single();
        
        if (error) return res.status(500).send('Database Error');
        
        if (connectionString) {
            await quickAddJob({ connectionString }, "scan_repo", { repo, token, scanId: scanRecord.id, userId });
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

app.use(Sentry.Handlers.errorHandler());
setInterval(() => { if (process.env.RENDER_EXTERNAL_URL) fetch(`${process.env.RENDER_EXTERNAL_URL}/`).catch(()=>{}); }, 14 * 60 * 1000);
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Receptionist running on ${PORT}`);
    startWorker().catch(e => { console.error("Worker failed to start:", e); Sentry.captureException(e); });
});