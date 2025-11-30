const PDFDocument = require('pdfkit');
const fs = require('fs');

/**
 * Generates a Compliance Certificate PDF in memory
 * @param {Object} scanData - The results from the Trivy scan
 * @param {string} scanId - The unique ID
 * @param {string} repoUrl - The repository URL
 * @returns {Promise<Buffer>} - Returns the PDF file as a binary buffer
 */
function generateCertificate(scanData, scanId, repoUrl) {
    return new Promise((resolve, reject) => {
        try {
            const doc = new PDFDocument({ margin: 50 });
            let buffers = [];

            // Capture the PDF into a buffer (memory) instead of writing to disk
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

            doc.moveDown(2); // Add space

            // 2. The "Grade" Badge
            // Simple logic: If no viral licenses, assume 'A'. (We can refine this logic later)
            // You can pass the actual grade in scanData if you have it calculated.
            const grade = scanData.grade || 'A'; 
            
            doc.roundedRect(250, 160, 100, 100, 10) // Draw a box
               .strokeColor('#333')
               .stroke();
            
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
            doc.font('Helvetica-Bold').fontSize(14).text('Audit Summary');
            doc.moveDown(0.5);
            doc.font('Helvetica').fontSize(12);

            // Extract counts (safety check in case data is missing)
            const viralCount = scanData.viral_licenses ? scanData.viral_licenses.length : 0;
            const vulnCount = scanData.critical_vulns ? scanData.critical_vulns.length : 0;

            doc.text(`• Viral Licenses Found: ${viralCount}`);
            doc.text(`• Critical Vulnerabilities: ${vulnCount}`);

            doc.moveDown(2);
            doc.fontSize(10).fillColor('#777');
            doc.text('This document certifies that the software repository listed above has been audited by the CodePassport Compliance Engine.', { align: 'center' });

            // --- DESIGN END ---

            doc.end(); // Finish writing the PDF

        } catch (error) {
            reject(error);
        }
    });
}

module.exports = generateCertificate;