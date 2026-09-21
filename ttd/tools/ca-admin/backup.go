package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// backup / restore move the whole CA directory as one .tar.gz. CA private
// keys travel in whatever form they are on disk — encrypted when
// PQC_CA_PASSPHRASE was used at init (Rencana V1 §13.2 backup requirement,
// §29 "simpan offline ... audit ceremony").

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory to back up")
	out := fs.String("out", "", "output .tar.gz (default: ca-backup-<ts>.tar.gz)")
	_ = fs.Parse(args)

	s, err := open(*dir)
	if err != nil {
		return err
	}
	target := *out
	if target == "" {
		target = fmt.Sprintf("ca-backup-%s.tar.gz", time.Now().UTC().Format("20060102T150405Z"))
	}

	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	root := filepath.Clean(*dir)
	count := 0
	err = filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(filepath.Dir(root), path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if _, err := io.Copy(tw, in); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	_ = s.logCeremony("ca.backup", target+" ("+fmt.Sprint(count)+" files)")
	fmt.Printf("backup written: %s (%d files)\n", target, count)
	fmt.Println("Store this on encrypted media, in a location separate from the CA machine (§13.2).")
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	in := fs.String("in", "", "backup .tar.gz (required)")
	dir := fs.String("dir", "", "destination directory (must not exist; required)")
	_ = fs.Parse(args)
	if *in == "" || *dir == "" {
		return errors.New("-in and -dir are required")
	}
	if _, err := os.Stat(*dir); err == nil {
		return fmt.Errorf("%s already exists; restore refuses to overwrite", *dir)
	}

	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	// Every archive entry starts with the original CA dir name; drop that
	// first segment and re-root everything under the requested --dir, so the
	// archived name never has to match the destination.
	dest := filepath.Clean(*dir)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(hdr.Name))
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}
		parts := strings.SplitN(clean, string(filepath.Separator), 2)
		if len(parts) < 2 { // the top-level dir entry itself
			continue
		}
		dst := filepath.Join(dest, parts[1])
		if rel, _ := filepath.Rel(dest, dst); strings.HasPrefix(rel, "..") {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
			count++
		}
	}

	s, err := open(*dir)
	if err != nil {
		return fmt.Errorf("restore incomplete: %w", err)
	}
	root, err := s.Root()
	if err != nil {
		return fmt.Errorf("restored CA is unusable: %w", err)
	}
	fmt.Printf("restored %d files to %s/\n  root fp %x\n", count, *dir, sha256Bytes(root.Cert.Raw))
	if name, leak := s.hasPrivateKeyLeak(); leak {
		return fmt.Errorf("GATE FAIL after restore: public/%s has private key material", name)
	}
	fmt.Println("gate OK: public/ contains no private key material")
	return nil
}
