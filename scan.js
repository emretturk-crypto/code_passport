const express = require('express');
const { execSync } = require('child_process');
const { createClient } = require('@supabase/supabase-js');
// Import the PDF Generator
const generateCertificate = require('./generateCertificate'); 

const app = express();

app.use(express.json());

// --- CONFIGURATION ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/', (req, res) => res.send('Harmonized Audit Engine Ready'));

// --- LOOP 1: THE RECEPTIONIST ---
app.post('/scan', async (req, res) => {
    const { repo, token } = req.body;
    if (!repo) return res.status(400).send('No repo provided');

    console.log(`🚀 Request Received for: ${repo}`);

    try {
        // 1. Create DB Record (Get ID)
        const { data: scanRecord, error: dbError } = await supabase
            .from('scans')
            .insert([{ 
                repo_url: repo, 
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

        // 2. Reply Immediately
        res.json({
            message: "Scan Started Successfully",
            scan_id: scanId,
            status: "RUNNING"
        });

        // 3. Trigger Background Work
        runBackgroundScan(repo, token, scanId);

    } catch (error) {
        console.error('Init Failed:', error.message);
        if (!res.headersSent) res.status(500).json({ error: error.message });
    }
});

// --- LOOP 2: THE WORKER ---
async function runBackgroundScan(repo, token, scanId) {
    console.log(`⚡ Background Scan Started for ID: ${scanId}`);
    let scanResults; 
    let status;
    let grade;
    let pdfBuffer;

    try {
        // A. AUTHENTICATION LOGIC
        let authRepo = repo;
        if (token && repo.includes('github.com')) {
            const cleanUrl = repo.replace('https://', '');
            authRepo = `https://${token}@${cleanUrl}`;
        }

        // B. TRIVY SCAN (Heavy Lifting)
        const command = `trivy repo ${authRepo} --scanners license,vuln --format json --timeout 30m --quiet`;
        const output = execSync(command, { encoding: 'utf-8', maxBuffer: 100 * 1024 * 1024 });
        scanResults = JSON.parse(output);

        // C. ANALYZE RISKS
        let viralLicenses = [];
        let criticalVulns = [];
        let highVulnsCount = 0;

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
                        if (vuln.Severity === 'HIGH') {
                            highVulnsCount++;
                        }
                    });
                }
            });
        }

        // D. GRADING LOGIC
        grade = 'A';
        if (viralLicenses.length > 0) grade = 'F';
        else if (criticalVulns.length > 0) grade = 'C';
        status = (grade === 'F') ? "FAILED" : "COMPLETED";

        // E. NATIVE PDF GENERATION
        console.log(`🎨 Generating PDF Certificate...`);
        
        const generationData = {
            grade: grade,
            viral_licenses: viralLicenses,
            critical_vulns: criticalVulns
        };
        
        pdfBuffer = await generateCertificate(generationData, scanId, repo);
        
        // F. UPLOAD TO SUPABASE (The Harmonized Fix)
        const fileName = `${scanId}.pdf`;

        // 🛑 FIX: Clean the Supabase URL to prevent double slashes
        // If supabaseUrl ends with '/', remove it. Otherwise keep it.
        const cleanSupabaseUrl = supabaseUrl.endsWith('/') ? supabaseUrl.slice(0, -1) : supabaseUrl;

        const { data: uploadData, error: uploadError } = await supabase.storage
            .from('audits') // Using your clean 'audits' bucket
            .upload(fileName, pdfBuffer, {
                contentType: 'application/pdf',
                upsert: true // Allows overwriting
            });

        if (uploadError) throw new Error(`Supabase Upload Failed: ${uploadError.message}`);

        // Construct the PERFECT Public URL
        const pdfUrl = `${cleanSupabaseUrl}/storage/v1/object/public/audits/${fileName}`;
        // G. UPDATE DATABASE
        await supabase
            .from('scans')
            .update({ 
                status: status,
                risk_grade: grade,
                pdf_url: pdfUrl,
                // findings_json removed to prevent payload too large error
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
app.listen(PORT, () => console.log(`Harmonized Audit Engine running on ${PORT}`));