// Command backup makes a "pseudo-snapshot" of a host: it archives the
// important folders red teams like to wipe or deface (/etc, DNS zones, web
// roots, ...) and the state of any running Docker containers, with a
// sha256-checksummed manifest so restoration is verifiable. It is OS-aware and
// can also restore from a previous snapshot. We cannot snapshot the VM itself,
// so this captures the parts that matter for recovery.
package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wrccdc/internal/common"
)

type fileArchive struct {
	Source  string `json:"source"`
	Archive string `json:"archive"`
	Files   int    `json:"files"`
	Skipped int    `json:"skipped"`
	Sha256  string `json:"sha256"`
	Error   string `json:"error,omitempty"`
}

type volArchive struct {
	Name    string `json:"name"`
	Archive string `json:"archive"`
	Sha256  string `json:"sha256"`
	Method  string `json:"method"`
	Error   string `json:"error,omitempty"`
}

type dockerContainer struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Image        string       `json:"image"`
	ImageArchive string       `json:"image_archive"`
	ImageSha256  string       `json:"image_sha256"`
	Inspect      string       `json:"inspect"`
	Volumes      []volArchive `json:"volumes"`
	Error        string       `json:"error,omitempty"`
}

type manifest struct {
	Host    string            `json:"host"`
	OS      string            `json:"os"`
	Created string            `json:"created"`
	Files   []fileArchive     `json:"files"`
	Docker  []dockerContainer `json:"docker"`
	Notes   []string          `json:"notes"`
}

func main() {
	info := common.Detect()

	var (
		outBase   = flag.String("out", filepath.Join(common.SecretDir(info), "snapshots"), "base directory for snapshots")
		pathsFlag = flag.String("paths", "", "comma-separated folders to back up (overrides the OS defaults)")
		extra     = flag.String("add", "", "comma-separated extra folders to back up in addition to defaults")
		noDocker  = flag.Bool("no-docker", false, "skip Docker container/volume backup")
		mirror    = flag.String("mirror", "", "also copy the finished snapshot to this directory (e.g. a second disk)")
		restore   = flag.String("restore", "", "restore from this snapshot directory instead of creating one")
		inPlace   = flag.Bool("in-place", false, "restore: extract to the live filesystem root instead of a staging folder")
		force     = flag.Bool("force", false, "restore: required to actually overwrite files")
	)
	flag.Parse()

	if *restore != "" {
		doRestore(info, *restore, *inPlace, *force)
		return
	}

	// --- snapshot ---
	ts := time.Now().Format("20060102_150405")
	snapDir := filepath.Join(*outBase, info.Hostname+"-"+ts)
	filesDir := filepath.Join(snapDir, "files")
	dockerDir := filepath.Join(snapDir, "docker")
	if err := os.MkdirAll(filesDir, 0o700); err != nil {
		common.Fatal("create snapshot dir: %v", err)
	}

	man := manifest{Host: info.Hostname, OS: info.OS, Created: time.Now().Format(time.RFC3339)}
	if !common.IsPrivileged() {
		man.Notes = append(man.Notes, "WARNING: not run as root/Administrator; some protected files were unreadable and skipped")
		common.Warn("not elevated: some protected files will be skipped")
	}

	targets := defaultPaths(info)
	if *pathsFlag != "" {
		targets = common.SplitCSV(*pathsFlag)
	}
	targets = append(targets, common.SplitCSV(*extra)...)

	common.Info("snapshotting %d candidate folders into %s", len(targets), snapDir)
	for _, t := range targets {
		if _, err := os.Stat(t); err != nil {
			common.Info("skip %s (%v)", t, errKind(err))
			continue
		}
		arcName := sanitize(t) + ".tar.gz"
		arcPath := filepath.Join(filesDir, arcName)
		files, skipped, sha, err := common.TarGz(t, arcPath)
		fa := fileArchive{Source: t, Archive: filepath.Join("files", arcName), Files: files, Skipped: skipped, Sha256: sha}
		if err != nil {
			fa.Error = err.Error()
			common.Warn("archive %s: %v", t, err)
		} else {
			common.Good("archived %s (%d files, %d skipped)", t, files, skipped)
		}
		man.Files = append(man.Files, fa)
	}

	if !*noDocker && common.Have("docker") {
		if err := os.MkdirAll(dockerDir, 0o700); err == nil {
			man.Docker = backupDocker(info, dockerDir, ts, &man)
		}
	} else if !*noDocker {
		man.Notes = append(man.Notes, "docker not installed; container backup skipped")
	}

	writeManifest(snapDir, man)
	common.Good("snapshot complete: %s", snapDir)

	if *mirror != "" {
		mirrorSnapshot(snapDir, *mirror)
	}
}

func backupDocker(info common.OSInfo, dockerDir, ts string, man *manifest) []dockerContainer {
	ps := common.Run("docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}")
	if !ps.OK() {
		man.Notes = append(man.Notes, "docker ps failed: "+common.Sanitize(ps.Stderr))
		return nil
	}
	var result []dockerContainer
	for _, line := range strings.Split(strings.TrimSpace(ps.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 2 {
			continue
		}
		id, name := cols[0], cols[1]
		image := ""
		if len(cols) >= 3 {
			image = cols[2]
		}
		common.Info("backing up container %s (%s)", name, id)
		dc := dockerContainer{ID: id, Name: name, Image: image}

		// inspect
		insp := common.Run("docker", "inspect", id)
		if insp.OK() {
			p := filepath.Join(dockerDir, name+".inspect.json")
			os.WriteFile(p, []byte(insp.Stdout), 0o600)
			dc.Inspect = filepath.Join("docker", name+".inspect.json")
		}

		// commit live state to an image, then save+gzip it
		tag := "wrccdc-snap/" + strings.ToLower(sanitize(name)) + ":" + ts
		if c := common.Run("docker", "commit", id, tag); c.OK() {
			tar := filepath.Join(dockerDir, name+".image.tar")
			if s := common.Run("docker", "save", tag, "-o", tar); s.OK() {
				gz := tar + ".gz"
				if err := gzipFile(tar, gz); err == nil {
					os.Remove(tar)
					sha, _ := common.Sha256File(gz)
					dc.ImageArchive = filepath.Join("docker", name+".image.tar.gz")
					dc.ImageSha256 = sha
				} else {
					dc.ImageArchive = filepath.Join("docker", name+".image.tar")
				}
			} else {
				dc.Error = "docker save: " + common.Sanitize(s.Stderr)
			}
			// Remove the temporary snapshot image to reclaim space.
			common.Run("docker", "image", "rm", tag)
		} else {
			dc.Error = "docker commit: " + common.Sanitize(c.Stderr)
		}

		dc.Volumes = backupVolumes(info, id, name, dockerDir)
		result = append(result, dc)
	}
	return result
}

// backupVolumes archives each named volume mounted into the container.
func backupVolumes(info common.OSInfo, id, name, dockerDir string) []volArchive {
	format := `{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}{{"\n"}}{{end}}`
	insp := common.Run("docker", "inspect", "--format", format, id)
	if !insp.OK() {
		return nil
	}
	var vols []volArchive
	for _, line := range strings.Split(strings.TrimSpace(insp.Stdout), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) < 3 || parts[0] != "volume" || parts[1] == "" {
			continue // skip binds (covered by folder backups) and anonymous mounts
		}
		volName, source := parts[1], parts[2]
		arcRel := filepath.Join("docker", name+".vol."+sanitize(volName)+".tar.gz")
		arcPath := filepath.Join(dockerDir, name+".vol."+sanitize(volName)+".tar.gz")
		va := volArchive{Name: volName, Archive: arcRel}

		// Preferred: archive the volume's host mountpoint directly (Linux root).
		if source != "" {
			if _, err := os.Stat(source); err == nil {
				if _, _, sha, err := common.TarGz(source, arcPath); err == nil {
					va.Sha256, va.Method = sha, "mountpoint"
					vols = append(vols, va)
					continue
				}
			}
		}
		// Fallback: tar from inside a throwaway container.
		hostDir, _ := filepath.Abs(dockerDir)
		run := common.Run("docker", "run", "--rm",
			"-v", volName+":/v:ro", "-v", hostDir+":/backup",
			"alpine", "sh", "-c",
			"tar czf /backup/"+name+".vol."+sanitize(volName)+".tar.gz -C /v .")
		if run.OK() {
			va.Sha256, _ = common.Sha256File(arcPath)
			va.Method = "container-tar"
		} else {
			va.Error = "could not back up volume (mountpoint unreachable and 'alpine' image unavailable)"
		}
		vols = append(vols, va)
	}
	return vols
}

func writeManifest(snapDir string, man manifest) {
	data, _ := json.MarshalIndent(man, "", "  ")
	os.WriteFile(filepath.Join(snapDir, "MANIFEST.json"), data, 0o600)
}

func sanitize(p string) string {
	r := strings.NewReplacer(`/`, "_", `\`, "_", ":", "_", " ", "_")
	s := strings.Trim(r.Replace(p), "_")
	if s == "" {
		s = "root"
	}
	return s
}

func errKind(err error) string {
	if os.IsNotExist(err) {
		return "not present"
	}
	return err.Error()
}
