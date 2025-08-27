
package internal
import (
    "bytes"
    "compress/gzip"
    "fmt"
    "io"
    "os"
)
// DecompressGzipFile reads a gzip-compressed file and returns the decompressed content as a string.
func DecompressGzipFile(filename string) (string, error) {
    f, err := os.Open(filename)
    if err != nil {
        return "", fmt.Errorf("error opening file: %w", err)
    }
    defer f.Close()
    var buf bytes.Buffer
    _, err = io.Copy(&buf, f)
    if err != nil {
        return "", fmt.Errorf("error reading file: %w", err)
    }
    gr, err := gzip.NewReader(&buf)
    if err != nil {
        return "", fmt.Errorf("error creating gzip reader: %w", err)
    }
    defer gr.Close()
    decompressed, err := io.ReadAll(gr)
    if err != nil {
        return "", fmt.Errorf("error decompressing: %w", err)
    }
    return string(decompressed), nil
}
