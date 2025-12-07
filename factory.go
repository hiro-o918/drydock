package drydock

import (
	"fmt"
	"io"

	"github.com/hiro-o918/drydock/exporter"
)

func NewExporter(format OutputFormat, writer io.Writer) (Exporter, error) {
	switch format {
	case OutputFormatJSON:
		return exporter.NewJSONExporter(writer), nil
	case OutputFormatCSV:
		return exporter.NewCSVExporter(writer), nil
	case OutputFormatTSV:
		return exporter.NewTSVExporter(writer), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}
