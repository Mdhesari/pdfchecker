package pdfchecker

import (
	"bytes"
	"errors"
	"regexp"
)

// Version is the current semantic version of the pdfchecker package.
const Version = "0.1.3"

var (
	ErrMaliciousPDF         = errors.New("PDF contains potentially malicious content")
	ErrInvalidPDFStructure  = errors.New("invalid PDF structure")
	ErrJavaScriptDetected   = errors.New("JavaScript detected in PDF")
	ErrFormDetected         = errors.New("interactive forms detected in PDF")
	ErrExternalRefDetected  = errors.New("external references detected in PDF")
	ErrEmbeddedFileDetected = errors.New("embedded files detected in PDF")
)

// Precompiled regular expressions used for detection to avoid repeated compilation
var (
	whitespaceRegex = regexp.MustCompile(`\s+`)

	jsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/\s*JavaScript`),
		regexp.MustCompile(`(?i)/\s*JS`),
		regexp.MustCompile(`(?i)/\s*OpenAction`),
		regexp.MustCompile(`(?i)app\s*\.`),
		regexp.MustCompile(`(?i)eval\s*\(`),
		regexp.MustCompile(`(?i)document\s*\.`),
		regexp.MustCompile(`(?i)this\s*\.`),
		regexp.MustCompile(`(?i)getField\s*\(`),
		regexp.MustCompile(`(?i)submitForm\s*\(`),
		regexp.MustCompile(`(?i)importDataObject\s*\(`),
		// Direct hex-obfuscated JS inside JS() calls
		regexp.MustCompile(`(?i)JS\(\s*#(?:[0-9A-Fa-f]{2,})+`),
	}

	jsHexRx     = regexp.MustCompile(`#(?:[0-9A-Fa-f]{2}){4,}`)
	jsHexAngle  = regexp.MustCompile(`<([0-9A-Fa-f]{4,})>`)
	jsWordRegex = regexp.MustCompile(`(?i)javascript|js`)

	formPatternsRegex = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/\s*AcroForm`),
		regexp.MustCompile(`(?i)/\s*XFA`),
		regexp.MustCompile(`(?i)/\s*Widget`),
		regexp.MustCompile(`(?i)/\s*FT\s*/\s*Tx`),
		regexp.MustCompile(`(?i)/\s*FT\s*/\s*Ch`),
		regexp.MustCompile(`(?i)/\s*FT\s*/\s*Btn`),
		regexp.MustCompile(`(?i)/\s*FT\s*/\s*Sig`),
	}

	externalRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/\s*GoToR`),
		regexp.MustCompile(`(?i)/\s*Launch`),
		regexp.MustCompile(`(?i)/\s*ImportData`),
		regexp.MustCompile(`(?i)/\s*SubmitForm`),
		regexp.MustCompile(`(?i)/\s*URI\b`),
		regexp.MustCompile(`(?i)URI\s*\(`),
		regexp.MustCompile(`(?i)\bhttps?://`),
		regexp.MustCompile(`(?i)\bfile://`),
		regexp.MustCompile(`(?i)\bftp://`),
	}

	embeddedFilesRegex = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/\s*EmbeddedFile`),
		regexp.MustCompile(`(?i)/\s*FileAttachment`),
		regexp.MustCompile(`(?i)/\s*Filespec`),
	}
)

// Check performs comprehensive security validation on PDF content
func Check(data []byte) error {
	if len(data) == 0 {
		return ErrInvalidPDFStructure
	}

	// Check PDF header: allow header to appear within the first 1024 bytes (some files have leading garbage)
	limit := 1024
	if len(data) < limit {
		limit = len(data)
	}
	if !bytes.Contains(data[:limit], []byte("%PDF-")) {
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
	// Remove stream bodies first to avoid matching binary data inside streams (Flate/JPX/etc.)
	streamRx := regexp.MustCompile(`(?is)stream\b.*?endstream`)
	contentNoStreams := streamRx.ReplaceAllString(content, " ")

	// Normalize whitespace to reduce obfuscation via spacing
	normalized := whitespaceRegex.ReplaceAllString(contentNoStreams, " ")

	for _, rx := range jsPatterns {
		if rx.MatchString(normalized) {
			return ErrJavaScriptDetected
		}
	}

	// Detect hex-encoded JS fragments (#...) and look for nearby JS markers outside streams
	locs := jsHexRx.FindAllStringIndex(contentNoStreams, -1)
	for _, loc := range locs {
		start := loc[0]
		from := start - 80
		if from < 0 {
			from = 0
		}
		ctx := contentNoStreams[from:start]
		if jsWordRegex.MatchString(ctx) {
			return ErrJavaScriptDetected
		}
	}

	// Angle-bracket hex objects + presence of JS tokens (outside streams)
	if jsHexAngle.MatchString(contentNoStreams) && jsWordRegex.MatchString(contentNoStreams) {
		return ErrJavaScriptDetected
	}

	return nil
}

// checkForForms detects interactive forms in PDF
func checkForForms(content string) error {
	for _, rx := range formPatternsRegex {
		if rx.MatchString(content) {
			return ErrFormDetected
		}
	}

	return nil
}

// checkForExternalReferences detects external references in PDF
func checkForExternalReferences(content string) error {
	// Normalize whitespace to reduce obfuscation
	normalized := whitespaceRegex.ReplaceAllString(content, " ")

	for _, rx := range externalRegexes {
		if rx.MatchString(normalized) {
			return ErrExternalRefDetected
		}
	}

	return nil
}

// checkForEmbeddedFiles detects embedded files in PDF
func checkForEmbeddedFiles(content string) error {
	for _, rx := range embeddedFilesRegex {
		if rx.MatchString(content) {
			return ErrEmbeddedFileDetected
		}
	}

	return nil
}

// Note: sanitization via regex-based replacement was removed because it is
// unsafe and can corrupt PDFs; prefer a parser-based approach to perform
// object-level sanitization when needed.
