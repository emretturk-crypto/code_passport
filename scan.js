const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
const app = express();

app.use(express.json());

// --- CONFIGURATION ---
// 1. Database Keys
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// 2. Make.com Webhook (The "Receiver" we just built)
// I pasted your specific URL here from the screenshot
const MAKE_CALLBACK_URL = "https://hook.eu2.make.com/b3i1fge4oqd94pfrgtu1fu53eizyyg7u";

app.get('/', (req, res) => res.send('Async Audit Engine Ready'));

// --- THE ENDPOINT (Loop 1: The Receptionist) ---
app.post('/scan', async (req, res) => {
    const { repo, token } = req.body;
    if (!repo) return res.status(400).send('No repo provided');

    console.log(`🚀 Request Received for: ${repo}`);

    try {
        // 1. Create the "Queued" Record in DB
        // This gives us a Scan ID immediately
        const { data: scanRecord, error: dbError } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
                status: 'RUNNING', // UI shows "Processing..."
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

        // 2. IMMEDIATE RESPONSE (The "Fire and Forget")
        // We tell the browser/Make.com: "We got it. Goodbye."
        res.json({
            message: "Scan Started Successfully",
            scan_id: scanId,
            status: "RUNNING"
        });

        // 3. TRIGGER BACKGROUND WORK
        // We do NOT await this. We let it run in the background.
        runBackgroundScan(repo, token, scanId);

    } catch (error) {
        console.error('Init Failed:', error.message);
        // Only if we haven't sent a response yet
        if (!res.headersSent) res.status(500).json({ error: error.message });
    }
});

// --- THE WORKER (Loop 2: The Background Process) ---
async function runBackgroundScan(repo, token, scanId) {
    console.log(`⚡ Background Scan Started for ID: ${scanId}`);

    try {
        // A. Prepare Auth
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
            const cleanUrl = repo.replace('https://', '');
            authRepo = `https://${token}@${cleanUrl}`;
        }

        // B. Run Trivy (Heavy Lifting)
        // Note: execSync pauses the Node process, but since response is sent, user doesn't care.
        const command = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
        const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
        const json = JSON.parse(output);

        // C. Analyze Risks (The "Brain")
        let viralLicenses = [];
        let criticalVulns = [];
        let highVulnsCount = 0;
        let totalDeps = 0; // Placeholder, Trivy JSON structure varies slightly for counts

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
                            criticalVulns.push({ id: vuln.VulnerabilityID, pkg: vuln.PkgName, severity: 'CRITICAL' });
                        }
                        if (vuln.Severity === 'HIGH') {
                            highVulnsCount++;
                        }
                    });
                }
            });
        }

        // D. Calculate Grade
        let grade = 'A';
        if (viralLicenses.length > 0) grade = 'F';
        else if (criticalVulns.length > 0) grade = 'C';

        const status = (grade === 'F') ? "FAILED" : "COMPLETED";

        // E. Save to Database (The Memory)
        await supabase
            .from('scans')
            .update({ 
                status: status,
                risk_grade: grade,
                findings_json: json,
                completed_at: new Date().toISOString()
            })
            .eq('id', scanId);

        console.log(`💾 Database Updated for ${scanId}`);

        // F. CALL MAKE.COM (The Handover)
        // We construct the payload exactly like our "Contract"
        const payload = {
            scan_id: scanId,
            status: status,
            meta: {
                repo_url: repo,
                engine: "Trivy v0.48.3"
            },
            results: {
                overall_grade: grade,
                is_compliant: (grade === 'A' || grade === 'B')
            },
            summary: {
                critical_vulnerabilities: criticalVulns.length,
                high_vulnerabilities: highVulnsCount,
                viral_licenses_count: viralLicenses.length
            },
            details: {
                viral_licenses: viralLicenses,
                top_vulnerabilities: criticalVulns.slice(0, 5) // Send top 5 to keep JSON light
            }
        };

        // Use built-in fetch (Node 18+)
        await fetch(MAKE_CALLBACK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        console.log(`✅ Callback sent to Make.com for ${scanId}`);

    } catch (err) {
        console.error(`❌ Background Scan Failed: ${err.message}`);
        // Attempt to mark as failed in DB
        await supabase.from('scans').update({ status: 'ERROR' }).eq('id', scanId);
    }
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Async Audit Engine running on ${PORT}`));