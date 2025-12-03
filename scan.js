const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const generateCertificate = require('./generateCertificate'); 

const app = express();

// ✅ NEW: ALLOW BROWSERS TO TALK TO US (CORS)
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); // Allow any website (Lovable)
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); // Allow these actions
    
    // If browser asks "Can I post?", say YES immediately
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(express.json());

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/', (req, res) => res.send('Harmonized Audit Engine Ready'));

app.post('/scan', async (req, res) => {
    // ✅ NEW: We now accept userId from the frontend
    const { repo, token, userId } = req.body; 
    
    if (!repo) return res.status(400).send('No repo provided');
    // We don't block if userId is missing, but it's good to have

    console.log(`🚀 Request Received for: ${repo}`);

    try {
        // 1. Create DB Record
        const { data: scanRecord, error: dbError } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                user_id: userId, // ✅ NEW: Links the scan to the user
                status: 'RUNNING',
                scanner_version: 'Trivy v0.48.3',
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (dbError) {
            console.error('DB Error:', dbError);
            return res.status(500).send('Database Init Failed');
        }

        const scanId = scanRecord.id;

        res.json({
            message: "Scan Started Successfully",
            scan_id: scanId,
            status: "RUNNING"
        });

        runBackgroundScan(repo, token, scanId);

    } catch (error) {
        console.error('Init Failed:', error.message);
        if (!res.headersSent) res.status(500).json({ error: error.message });
    }
});

async function runBackgroundScan(repo, token, scanId) {
    console.log(`⚡ Background Scan Started for ID: ${scanId}`);
    let scanResults; 
    let status;
    let grade;
    let pdfBuffer;

    try {
        // ... (Scanning Logic remains the same) ...
        // B. TRIVY SCAN
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
           const cleanUrl = repo.replace('https://', '');
           authRepo = `https://${token}@${cleanUrl}`;
        }
        
        // Shortened for brevity (The logic you pasted was fine here)
        const command = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
        const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
        scanResults = JSON.parse(output);

        // ... (Analysis Logic remains the same) ...
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

        grade = 'A';
        if (viralLicenses.length > 0) grade = 'F';
        else if (criticalVulns.length > 0) grade = 'C';
        status = (grade === 'F') ? "FAILED" : "COMPLETED";

        // E. PDF GENERATION
        console.log(`🎨 Generating PDF Certificate...`);
        const generationData = {
            grade: grade,
            viral_licenses: viralLicenses,
            critical_vulns: criticalVulns
        };
        pdfBuffer = await generateCertificate(generationData, scanId, repo);
        
        // F. UPLOAD TO SUPABASE
        // ✅ CORRECT: Using dynamic name based on ID
        const fileName = `${scanId}.pdf`; 
        
        // Clean URL to avoid double slash
        const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;

        const { error: uploadError } = await supabase.storage
            .from('audits') // ✅ CORRECT: Using 'audits' bucket
            .upload(fileName, pdfBuffer, {
                contentType: 'application/pdf',
                upsert: true 
            });

        if (uploadError) throw new Error(`Supabase Upload Failed: ${uploadError.message}`);

        // ✅ CORRECT: Constructing URL for 'audits' bucket
        const pdfUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${fileName}`;

        // G. UPDATE DATABASE
        await supabase
            .from('scans')
            .update({ 
                status: status,
                risk_grade: grade,
                pdf_url: pdfUrl,
                completed_at: new Date().toISOString()
            })
            .eq('id', scanId);

        console.log(`💾 Database & Storage Updated for ${scanId}`);

    } catch (err) {
        console.error(`❌ Harmonized Scan Failed: ${err.message}`);
        await supabase.from('scans').update({ status: 'ERROR' }).eq('id', scanId);
    }
}

const PORT = process.env.PORT || 8080;
// --- KEEPER: PREVENT COLD STARTS ---
// Ping myself every 14 minutes to stay awake (Render sleeps after 15m)
const PING_INTERVAL = 14 * 60 * 1000; 

setInterval(() => {
    // Only ping if we are in production
    // You must set 'RENDER_EXTERNAL_URL' in your Render Dashboard Env Vars
    if (process.env.RENDER_EXTERNAL_URL) {
        console.log('💓 Sending Heartbeat to stay awake...');
        fetch(`${process.env.RENDER_EXTERNAL_URL}/`)
            .then(res => {
                if(res.ok) console.log(`💓 Heartbeat Successful`);
                else console.log(`💔 Heartbeat bounced: ${res.status}`);
            })
            .catch(err => console.error(`💔 Heartbeat Failed: ${err.message}`));
    }
}, PING_INTERVAL);

// ... app.listen is below this
app.listen(PORT, () => console.log(`Harmonized Audit Engine running on ${PORT}`));