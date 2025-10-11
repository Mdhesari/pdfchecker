package security

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
)

const (
	VERSION = "0.1.0"
)

var (
	ErrMaliciousPDF        = errors.New("PDF contains potentially malicious content")
	ErrInvalidPDFStructure = errors.New("invalid PDF structure")
	ErrJavaScriptDetected  = errors.New("JavaScript detected in PDF")
	ErrFormDetected        = errors.New("interactive forms detected in PDF")
	ErrExternalRefDetected = errors.New("external references detected in PDF")
)

// Check performs comprehensive security validation on PDF content
func Check(data []byte) error {
	if len(data) == 0 {
		return ErrInvalidPDFStructure
	}

	// Check PDF header
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return ErrInvalidPDFStructure
	}

	content := string(data)

	// Check for JavaScript
	if err := checkForJavaScript(content); err != nil {
		return err
	}

	// Check for interactive forms
	if err := checkForForms(content); err != nil {
		return err
	}

	// Check for external references
	if err := checkForExternalReferences(content); err != nil {
		return err
	}

	// Check for embedded files
	if err := checkForEmbeddedFiles(content); err != nil {
		return err
	}

	return nil
}

// checkForJavaScript detects JavaScript content in PDF
func checkForJavaScript(content string) error {
	jsPatterns := []string{
		`/\s*JavaScript`,
		`/\s*JS`,
		`/\s*OpenAction`,
		`app\s*\.`,
		`eval\s*\(`,
		`document\s*\.`,
		`this\s*\.`,
		`getField\s*\(`,
		`submitForm\s*\(`,
		`importDataObject\s*\(`,
	}

	// Remove extra whitespace and normalize content
	normalizedContent := regexp.MustCompile(`\s+`).ReplaceAllString(content, " ")
	contentLower := strings.ToLower(normalizedContent)

	for _, pattern := range jsPatterns {
		matched, _ := regexp.MatchString(strings.ToLower(pattern), contentLower)
		if matched {
			return ErrJavaScriptDetected
		}
	}

	return nil
}

// checkForForms detects interactive forms in PDF
func checkForForms(content string) error {
	formPatterns := []string{
		`/AcroForm`,
		`/XFA`,
		`/Widget`,
		`/Tx`,
		`/Ch`,
		`/Btn`,
		`/Sig`,
	}

	contentLower := strings.ToLower(content)

	for _, pattern := range formPatterns {
		matched, _ := regexp.MatchString(strings.ToLower(pattern), contentLower)
		if matched {
			return ErrFormDetected
		}
	}

	return nil
}

// checkForExternalReferences detects external references in PDF
func checkForExternalReferences(content string) error {
	externalPatterns := []string{
		`/URI`,
		`/GoToR`,
		`/Launch`,
		`/ImportData`,
		`/SubmitForm`,
		`http://`,
		`https://`,
		`ftp://`,
		`file://`,
	}

	contentLower := strings.ToLower(content)

	for _, pattern := range externalPatterns {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			return ErrExternalRefDetected
		}
	}

	return nil
}

// checkForEmbeddedFiles detects embedded files in PDF
func checkForEmbeddedFiles(content string) error {
	embeddedPatterns := []string{
		`/EmbeddedFile`,
		`/FileAttachment`,
		`/Filespec`,
	}

	contentLower := strings.ToLower(content)

	for _, pattern := range embeddedPatterns {
		matched, _ := regexp.MatchString(strings.ToLower(pattern), contentLower)
		if matched {
			return errors.New("embedded files detected in PDF")
		}
	}

	return nil
}

// SanitizePDF removes potentially dangerous content from PDF (basic implementation)
func SanitizePDF(data []byte) ([]byte, error) {
	// This is a basic implementation - in production, you'd want a more sophisticated approach
	content := string(data)

	// Remove JavaScript actions
	jsRemovalPatterns := []string{
		`/JavaScript[^>]*?>.*?</`,
		`/JS[^>]*?>.*?</`,
		`/OpenAction[^>]*?>.*?</`,
	}

	for _, pattern := range jsRemovalPatterns {
		re := regexp.MustCompile(pattern)
		content = re.ReplaceAllString(content, "")
	}

	return []byte(content), nil
}
