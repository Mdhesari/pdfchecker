# PDFChecker

PDFChecker is a pretty straight forward pdf security & mime checker.

## Install

```bash
go get github.com/mdhesari/pdfchecker
```

## Use

```go
import "github.com/mdhesari/pdfchecker"

// Check if PDF is valid
err := pdfchecker.Check([]byte{...})
```

## What it does

- Validates PDF structure
- Detects corruption
- Extracts metadata
- Reports file health

Fast. Reliable. Simple API.

## Why?

PDFs break. You need to know when. This tells you.

## License

MIT