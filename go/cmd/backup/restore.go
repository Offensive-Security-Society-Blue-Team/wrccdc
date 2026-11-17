package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"wrccdc/internal/common"
)

// gzipFile compresses src into dst (gzip).
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		return err
	}
	return gz.Close()
}

// mirrorSnapshot copies a finished snapshot directory to a second location so a
// single disk loss (or red-team wipe of the primary path) does not destroy the
// only copy.
func mirrorSnapshot(snapDir, mirrorBase string) {
	dst := filepath.Join(mirrorBase, filepath.Base(snapDir))
	common.Info("mirroring snapshot to %s", dst)
	err := filepath.Walk(snapDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(snapDir, path)
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyFile(path, target)
	})
	if err != nil {
		common.Warn("mirror failed: %v", err)
	} else {
		common.Good("mirror complete: %s", dst)
	}
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func doRestore(info common.OSInfo, snapDir string, inPlace, force bool) {
	data, err := os.ReadFile(filepath.Join(snapDir, "MANIFEST.json"))
	if err != nil {
		common.Fatal("read manifest: %v", err)
	}
	var man manifest
	if err := json.Unmarshal(data, &man); err != nil {
		common.Fatal("parse manifest: %v", err)
	}
	if inPlace && !force {
		common.Fatal("in-place restore overwrites live files; re-run with --in-place --force")
	}

	common.Info("restoring snapshot of %s taken %s", man.Host, man.Created)

	for _, fa := range man.Files {
		arc := filepath.Join(snapDir, fa.Archive)
		if fa.Sha256 != "" {
			if sha, err := common.Sha256File(arc); err == nil && sha != fa.Sha256 {
				common.Warn("checksum MISMATCH for %s (archive may be corrupt); skipping", fa.Archive)
				continue
			}
		}
		var dest string
		if inPlace {
			dest = filepath.Dir(fa.Source) // restores the folder to its original location
		} else {
			dest = filepath.Join(snapDir, "restored", sanitize(fa.Source))
			os.MkdirAll(dest, 0o700)
		}
		if err := common.UnTarGz(arc, dest); err != nil {
			common.Warn("restore %s: %v", fa.Source, err)
		} else {
			common.Good("restored %s -> %s", fa.Source, dest)
		}
	}

	// Docker images are safe to load (they do not touch running containers).
	if common.Have("docker") {
		for _, dc := range man.Docker {
			if dc.ImageArchive == "" {
				continue
			}
			arc := filepath.Join(snapDir, dc.ImageArchive)
			if r := common.Run("docker", "load", "-i", arc); r.OK() {
				common.Good("loaded image for container %s", dc.Name)
			} else {
				common.Warn("docker load %s: %s", dc.Name, common.Sanitize(r.Stderr))
			}
			if inPlace && force {
				restoreVolumes(dc, snapDir)
			}
		}
	}

	common.Good("restore finished")
	if !inPlace {
		common.Info("files were extracted into %s/restored for review; re-run with --in-place --force to overwrite the live paths", snapDir)
	}
}

func restoreVolumes(dc dockerContainer, snapDir string) {
	for _, v := range dc.Volumes {
		if v.Archive == "" {
			continue
		}
		arc := filepath.Join(snapDir, v.Archive)
		abs, _ := filepath.Abs(filepath.Dir(arc))
		common.Run("docker", "volume", "create", v.Name)
		r := common.Run("docker", "run", "--rm",
			"-v", v.Name+":/v", "-v", abs+":/backup",
			"alpine", "sh", "-c",
			"cd /v && tar xzf /backup/"+filepath.Base(arc))
		if r.OK() {
			common.Good("restored volume %s", v.Name)
		} else {
			common.Warn("restore volume %s: %s", v.Name, common.Sanitize(r.Stderr))
		}
	}
}
