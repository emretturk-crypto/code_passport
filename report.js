const PDFDocument = require('pdfkit');
const fs = require('fs');

// Read and parse the scan results
const scanData = fs.readFileSync('scan_results.json', 'utf-8');
const jsonContent = JSON.parse(scanData);

// Check if JSON contains 'AGPL' or 'GPL'
const jsonString = JSON.stringify(jsonContent);
const hasGPL = jsonString.includes('AGPL') || jsonString.includes('GPL');

// Create PDF document
const doc = new PDFDocument();
const output = fs.createWriteStream('Compliance_Certificate.pdf');
doc.pipe(output);

// Add title
doc.fontSize(24).text('CodePassport Compliance Report', { align: 'center' });

doc.moveDown(2);

// Add status
if (hasGPL) {
    doc.fontSize(18).fillColor('red').text('STATUS: FAILED', { align: 'center' });
} else {
    doc.fontSize(18).fillColor('green').text('STATUS: PASSED', { align: 'center' });
}

// Save and close the PDF
doc.end();

output.on('finish', () => {
    console.log('PDF saved as Compliance_Certificate.pdf');
});

