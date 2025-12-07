package exporter

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/hiro-o918/drydock/schemas"
)

// JSONExporter exports analysis results in JSON format
type JSONExporter struct {
	writer io.Writer
}

// NewJSONExporter creates a new JSONExporter with the specified writer
func NewJSONExporter(writer io.Writer) *JSONExporter {
	return &JSONExporter{
		writer: writer,
	}
}

// NewDefaultJSONExporter creates a new JSONExporter with default settings (stdout)
func NewDefaultJSONExporter() *JSONExporter {
	return NewJSONExporter(os.Stdout)
}

// Export outputs the analysis results in indented JSON format
func (e *JSONExporter) Export(ctx context.Context, results []schemas.AnalyzeResult) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	_, err = e.writer.Write(data)
	if err != nil {
		return err
	}

	// Append newline for clean terminal output
	_, err = e.writer.Write([]byte("\n"))
	return err
}
