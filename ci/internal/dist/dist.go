// Package dist writes the release archives of the tmb client
// (tmb_<version>_<os>_<arch>.tar.gz). The output depends only on the file
// contents, names, modes and the given mtime: entries are sorted, owners are
// root:root, there are no extended headers, and the gzip header carries no
// name and no time, so the same commit gives the same bytes on Linux and
// macOS.
package dist

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// File is one archive entry: Name inside the archive, Path on disk.
type File struct {
	Name string
	Path string
	Mode int64
}

// ParseFile reads "name=path" with mode 0755 (the archives carry executables).
func ParseFile(spec string) (File, error) {
	name, path, ok := strings.Cut(spec, "=")
	if !ok || name == "" || path == "" || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return File{}, fmt.Errorf("file %q: want name=path with a relative name", spec)
	}
	return File{Name: name, Path: path, Mode: 0o755}, nil
}

// WriteTarGz writes files as a deterministic tar.gz to w.
func WriteTarGz(w io.Writer, files []File, mtime time.Time) error {
	files = append([]File(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	for i, f := range files {
		if i > 0 && files[i-1].Name == f.Name {
			return fmt.Errorf("duplicate archive entry %s", f.Name)
		}
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.Name,
			Mode:     f.Mode,
			Size:     int64(len(data)),
			ModTime:  mtime.UTC().Truncate(time.Second),
			Uname:    "root",
			Gname:    "root",
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
