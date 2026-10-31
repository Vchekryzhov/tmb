// Package sbom writes CycloneDX 1.6 SBOMs for the release files of
// ci/run.sh dist: one BOM per deb, rpm or tar.gz, describing that file and
// the Go binaries inside it. Components come from the build info Go embeds
// in each binary (debug/buildinfo): the main package, every dependency
// module (none while the product stays stdlib-only) and the Go standard
// library at the toolchain version. The output depends only on its inputs:
// the timestamp is the commit time and the serial number is derived from the
// artifact hash, so two builds of one commit give the same bytes.
package sbom

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Artifact is the release file the BOM describes.
type Artifact struct {
	Path    string // file on disk, hashed
	Type    string // deb, rpm or archive
	Name    string // package name (tmb, tmb-broker)
	Version string // version as the package carries it
	OS      string // archive only: linux, darwin
	Arch    string // architecture as the file names it (amd64, x86_64, ...)
}

// Binary is one Go executable inside the artifact.
type Binary struct {
	Name string // path inside the artifact (/usr/bin/tmb, tmb)
	Path string // the same file on disk, read for build info and hashed
}

// Options are the BOM-wide fields.
type Options struct {
	Version  string    // product version (vX.Y.Z...), the binaries' version
	Time     time.Time // commit time (SOURCE_DATE_EPOCH)
	Supplier string
	URL      string // source repository
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type extRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type component struct {
	Type       string     `json:"type"`
	Ref        string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Purl       string     `json:"purl,omitempty"`
	Hashes     []hash     `json:"hashes,omitempty"`
	Properties []property `json:"properties,omitempty"`
	ExtRefs    []extRef   `json:"externalReferences,omitempty"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type bom struct {
	Format       string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []component `json:"components"`
		} `json:"tools"`
		Supplier  *supplier `json:"supplier,omitempty"`
		Component component `json:"component"`
	} `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type supplier struct {
	Name string   `json:"name"`
	URL  []string `json:"url,omitempty"`
}

// purlVersion escapes the characters of a version that a purl cannot carry
// raw ('+' of semver build metadata).
func purlVersion(v string) string { return strings.ReplaceAll(v, "+", "%2B") }

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// serial derives an RFC 4122 version-5-shaped UUID from the artifact hash.
func serial(sum string) string {
	b := sha256.Sum256([]byte("tmb-sbom:" + sum))
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b[:16])
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", x[0:8], x[8:12], x[12:16], x[16:20], x[20:32])
}

func artifactPurl(a Artifact) (string, error) {
	switch a.Type {
	case "deb", "rpm":
		return fmt.Sprintf("pkg:%s/%s@%s?arch=%s", a.Type, a.Name, purlVersion(a.Version), a.Arch), nil
	case "archive":
		if a.OS == "" {
			return "", fmt.Errorf("archive %s: OS is required", a.Path)
		}
		return fmt.Sprintf("pkg:generic/%s@%s?arch=%s&os=%s", a.Name, purlVersion(a.Version), a.Arch, a.OS), nil
	}
	return "", fmt.Errorf("artifact type %q: want deb, rpm or archive", a.Type)
}

// Write writes the BOM of a and its binaries to w.
func Write(w io.Writer, a Artifact, bins []Binary, o Options) error {
	if a.Name == "" || a.Version == "" || a.Arch == "" || len(bins) == 0 || o.Version == "" {
		return fmt.Errorf("artifact name, version, arch, a product version and at least one binary are required")
	}
	root, err := artifactPurl(a)
	if err != nil {
		return err
	}
	sum, err := fileSHA256(a.Path)
	if err != nil {
		return err
	}
	var b bom
	b.Format, b.SpecVersion, b.Version = "CycloneDX", "1.6", 1
	b.SerialNumber = serial(sum)
	b.Metadata.Timestamp = o.Time.UTC().Format(time.RFC3339)
	b.Metadata.Tools.Components = []component{{Type: "application", Ref: "tool:tmbci", Name: "tmbci"}}
	if o.Supplier != "" {
		b.Metadata.Supplier = &supplier{Name: o.Supplier}
		if o.URL != "" {
			b.Metadata.Supplier.URL = []string{o.URL}
		}
	}
	b.Metadata.Component = component{Type: "application", Ref: root, Name: a.Name, Version: a.Version, Purl: root,
		Hashes: []hash{{"SHA-256", sum}}}
	if o.URL != "" {
		b.Metadata.Component.ExtRefs = []extRef{{Type: "vcs", URL: o.URL}}
	}

	libs := map[string]component{}
	deps := map[string][]string{}
	rootDeps := []string{}
	sort.Slice(bins, func(i, j int) bool { return bins[i].Name < bins[j].Name })
	for i, bin := range bins {
		if i > 0 && bins[i-1].Name == bin.Name {
			return fmt.Errorf("duplicate binary %s", bin.Name)
		}
		info, err := buildinfo.ReadFile(bin.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", bin.Path, err)
		}
		bsum, err := fileSHA256(bin.Path)
		if err != nil {
			return err
		}
		purl := fmt.Sprintf("pkg:golang/%s@%s", info.Main.Path, purlVersion(o.Version))
		if sub := strings.TrimPrefix(info.Path, info.Main.Path+"/"); sub != info.Path {
			purl += "#" + sub
		}
		ref := "file:" + bin.Name
		c := component{Type: "application", Ref: ref, Name: info.Path, Version: o.Version, Purl: purl,
			Hashes: []hash{{"SHA-256", bsum}}, Properties: []property{{"tmb:path", bin.Name}, {"tmb:go", info.GoVersion}}}
		for _, s := range info.Settings {
			key := "cdx:gomod:build:" + s.Key
			if s.Key == strings.ToUpper(s.Key) && !strings.HasPrefix(s.Key, "-") {
				key = "cdx:gomod:build:env:" + s.Key
			}
			c.Properties = append(c.Properties, property{key, s.Value})
		}
		b.Components = append(b.Components, c)
		rootDeps = append(rootDeps, ref)

		std := "v" + strings.TrimPrefix(info.GoVersion, "go")
		stdRef := "pkg:golang/stdlib@" + purlVersion(std)
		libs[stdRef] = component{Type: "library", Ref: stdRef, Name: "stdlib", Version: std, Purl: stdRef}
		mine := []string{stdRef}
		for _, d := range info.Deps {
			if d.Replace != nil {
				d = d.Replace
			}
			dref := fmt.Sprintf("pkg:golang/%s@%s", d.Path, purlVersion(d.Version))
			libs[dref] = component{Type: "library", Ref: dref, Name: d.Path, Version: d.Version, Purl: dref}
			mine = append(mine, dref)
		}
		sort.Strings(mine)
		deps[ref] = mine
	}
	refs := make([]string, 0, len(libs))
	for r := range libs {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	for _, r := range refs {
		b.Components = append(b.Components, libs[r])
		deps[r] = []string{}
	}
	b.Dependencies = append(b.Dependencies, dependency{Ref: root, DependsOn: rootDeps})
	for _, c := range b.Components {
		b.Dependencies = append(b.Dependencies, dependency{Ref: c.Ref, DependsOn: deps[c.Ref]})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}
