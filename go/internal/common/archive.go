package common

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// TarGz walks src (a file or directory) and writes a gzip-compressed tar to
// dst. It returns the number of regular files archived and the sha256 of the
// resulting archive. Symlinks are stored as links (not followed) to avoid
// escaping the source tree or looping. Unreadable entries are skipped and
// counted in skipped rather than aborting the whole backup.
func TarGz(src, dst string) (files int, skipped int, sha string, err error) {
	src = filepath.Clean(src)
	out, err := os.Create(dst)
	if err != nil {
		return 0, 0, "", err
	}
	defer out.Close()

	hasher := sha256.New()
	mw := io.MultiWriter(out, hasher)
	gz := gzip.NewWriter(mw)
	tw := tar.NewWriter(gz)

	base := filepath.Dir(src)

	walkErr := filepath.Walk(src, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil {
			skipped++
			return nil // keep going past permission errors / vanished files
		}
		// Skip sockets, devices, pipes — not meaningful in a restore.
		mode := fi.Mode()
		if mode&(os.ModeSocket|os.ModeDevice|os.ModeNamedPipe|os.ModeCharDevice) != 0 {
			skipped++
			return nil
		}

		rel, rerr := filepath.Rel(base, path)
		if rerr != nil {
			skipped++
			return nil
		}
		rel = filepath.ToSlash(rel)

		var link string
		if mode&os.ModeSymlink != 0 {
			link, _ = os.Readlink(path)
		}
		hdr, herr := tar.FileInfoHeader(fi, link)
		if herr != nil {
			skipped++
			return nil
		}
		hdr.Name = rel
		if fi.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			skipped++
			return nil
		}
		if !mode.IsRegular() {
			return nil
		}
		f, oerr := os.Open(path)
		if oerr != nil {
			skipped++
			return nil
		}
		if _, cerr := io.Copy(tw, f); cerr != nil {
			f.Close()
			skipped++
			return nil
		}
		f.Close()
		files++
		return nil
	})

	// Close in order; report the first real error.
	if cerr := tw.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if cerr := gz.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if walkErr != nil && err == nil {
		err = walkErr
	}
	sha = hex.EncodeToString(hasher.Sum(nil))
	return files, skipped, sha, err
}

// UnTarGz extracts a gzip tar archive into destDir. It refuses entries whose
// cleaned path would escape destDir (path traversal guard). Existing files are
// overwritten.
func UnTarGz(archivePath, destDir string) error {
	in, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(destAbs, filepath.FromSlash(hdr.Name))
		// Path traversal guard.
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator),
			filepath.Clean(destAbs)+string(os.PathSeparator)) && filepath.Clean(target) != destAbs {
			return fmt.Errorf("refusing path traversal entry: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fi(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeSymlink:
			os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				// Non-fatal: some targets (Windows) may not allow symlinks.
				Warn("symlink %s -> %s: %v", target, hdr.Linkname, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

func fi(mode int64) os.FileMode {
	m := os.FileMode(mode).Perm()
	if m == 0 {
		m = 0o644
	}
	return m
}

// Sha256File returns the hex sha256 of a file on disk.
func Sha256File(path string) (string, error) {
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
