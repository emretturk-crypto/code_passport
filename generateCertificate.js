const PDFDocument = require('pdfkit');

/**
 * Generates a Compliance Certificate PDF in memory
 * @param {Object} scanData - The results (grade, viral_licenses, critical_vulns, leaked_secrets)
 * @param {string} scanId - The unique ID
 * @param {string} repoUrl - The repository URL
 * @returns {Promise<Buffer>} - Returns the PDF file as a binary buffer
 */
function generateCertificate(scanData, scanId, repoUrl) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({ margin: 50 });
            let buffers = [];

            // Capture the PDF into a buffer (memory)
            doc.on('data', (chunk) => buffers.push(chunk));
            doc.on('end', () => {
                const pdfData = Buffer.concat(buffers);
                resolve(pdfData);
            });

            // --- DESIGN START ---

            // 1. Header / Logo
            doc.fillColor('#002B5B') // Navy Blue
               .fontSize(24)
               .text('CodePassport.io', { align: 'center' })
               .moveDown(0.5);

            doc.fontSize(16)
               .text('Certificate of Software Compliance', { align: 'center' });

            doc.moveDown(2);

            // 2. The "Grade" Badge
            const grade = scanData.grade || 'A'; 
            
            // Draw Box
            doc.lineWidth(2);
            doc.roundedRect(250, 160, 100, 100, 10)
               .strokeColor(grade === 'A' ? '#008000' : '#FF0000')
               .stroke();
            
            // Draw Letter
            doc.fontSize(60)
               .fillColor(grade === 'A' ? '#008000' : '#FF0000') // Green for A, Red for others
               .text(grade, 250, 175, { width: 100, align: 'center' });
            
            doc.moveDown(5);

            // 3. Metadata Table
            doc.fontSize(12).fillColor('#333');
            const metaX = 50;
            const metaY = 300;

            doc.text('Repository:', metaX, metaY);
            doc.font('Helvetica-Bold').text(repoUrl, metaX + 100, metaY);
            
            doc.font('Helvetica').text('Scan ID:', metaX, metaY + 20);
            doc.font('Helvetica-Bold').text(scanId, metaX + 100, metaY + 20);

            doc.font('Helvetica').text('Date:', metaX, metaY + 40);
            doc.font('Helvetica-Bold').text(new Date().toISOString().split('T')[0], metaX + 100, metaY + 40);

            doc.moveDown(4);

            // 4. Summary
            doc.font('Helvetica-Bold').fontSize(14).fillColor('#000').text('Audit Summary');
            doc.moveDown(0.5);
            doc.font('Helvetica').fontSize(12);

            // Extract counts safely
            const viralCount = scanData.viral_licenses ? scanData.viral_licenses.length : 0;
            const vulnCount = scanData.critical_vulns ? scanData.critical_vulns.length : 0;
            const secretCount = scanData.leaked_secrets ? scanData.leaked_secrets.length : 0;

            doc.text(`• Viral Licenses Found: ${viralCount}`);
            doc.text(`• Critical Vulnerabilities: ${vulnCount}`);
            doc.text(`• Hardcoded Secrets: ${secretCount}`); 

            doc.moveDown(2);

            // ---------------------------------------------------------
            // 5. DETAILED FINDINGS (The Value Prop)
            // ---------------------------------------------------------

            // A. SECRETS (Gitleaks)
            if (secretCount > 0) {
                doc.addPage(); // Force a new page for sensitive details
                doc.font('Helvetica-Bold').fontSize(16).fillColor('#D32F2F').text('🚨 CRITICAL SECURITY LEAKS');
                doc.fontSize(10).fillColor('#555').text('The following hardcoded secrets were detected. Revoke these immediately.');
                doc.moveDown(1);

                scanData.leaked_secrets.forEach((secret, index) => {
                    doc.font('Helvetica-Bold').fontSize(12).fillColor('#000').text(`Leak #${index + 1}: ${secret.Description || secret.RuleID}`);
                    doc.font('Helvetica').fontSize(10).fillColor('#333');
                    doc.text(`File: ${secret.File}`);
                    doc.text(`Line: ${secret.StartLine}`);
                    // MASK THE SECRET for safety (Show first 4 chars only)
                    const safeSecret = secret.Secret ? `${secret.Secret.substring(0, 4)}...[REDACTED]` : '[HIDDEN]';
                    doc.text(`Snippet: ${safeSecret}`);
                    doc.moveDown(1);
                });
            }

            // B. VULNERABILITIES (Trivy)
            if (vulnCount > 0) {
                if (secretCount === 0) doc.addPage(); // New page if we haven't already
                else doc.moveDown(2);

                doc.font('Helvetica-Bold').fontSize(16).fillColor('#D32F2F').text('🔥 CRITICAL VULNERABILITIES');
                doc.fontSize(10).fillColor('#555').text('These packages have known critical CVEs.');
                doc.moveDown(1);

                scanData.critical_vulns.forEach((vuln, index) => {
                    doc.font('Helvetica-Bold').fontSize(12).fillColor('#000').text(`${vuln.PkgName} (${vuln.VulnerabilityID})`);
                    doc.font('Helvetica').fontSize(10).fillColor('#333');
                    doc.text(`Installed: ${vuln.InstalledVersion}`);
                    doc.text(`Fixed In: ${vuln.FixedVersion || 'No Fix Available'}`);
                    doc.text(`Title: ${vuln.Title || 'N/A'}`);
                    doc.moveDown(1);
                });
            }

            // C. VIRAL LICENSES
            if (viralCount > 0) {
                doc.moveDown(2);
                doc.font('Helvetica-Bold').fontSize(16).fillColor('#D32F2F').text('⚖️ VIRAL LICENSES DETECTED');
                doc.moveDown(1);

                scanData.viral_licenses.forEach((lic) => {
                    doc.font('Helvetica').fontSize(12).fillColor('#000').text(`• ${lic.pkg} uses ${lic.license}`);
                });
            }

            // Footer
            doc.moveDown(2);
            doc.fontSize(8).fillColor('#999').text('Generated by CodePassport.io', { align: 'center', baseline: 'bottom' });

            // --- DESIGN END ---

            doc.end();

        } catch (error) {
            reject(error);
        }
    }); 
} 

module.exports = generateCertificate;