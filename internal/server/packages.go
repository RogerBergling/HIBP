package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/google/uuid"
)

const maxPackageUploadSize = helper.MaxPackageSize

func (s *Server) jobPackageDir() string {
	return filepath.Join(filepath.Dir(s.store.Path()), "hibp-jobs")
}

func (s *Server) handlePackageInstallJob(w http.ResponseWriter, r *http.Request) {
	uploadLimit := int64(maxPackageUploadSize + (2 << 20))
	memoryLimit := int64(8 << 20)
	if s.demo != nil {
		uploadLimit = (8 << 20) + (2 << 20)
		memoryLimit = 4 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit)
	if err := r.ParseMultipartForm(memoryLimit); err != nil {
		writeError(w, http.StatusBadRequest, "invalid package upload: "+err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), "install") {
		writeError(w, http.StatusBadRequest, "confirm must be \"INSTALL\" for a package deployment")
		return
	}
	var hostIDs []string
	if raw := strings.TrimSpace(r.FormValue("host_ids")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &hostIDs); err != nil {
			writeError(w, http.StatusBadRequest, "host_ids must be a JSON array")
			return
		}
	}
	env := map[string]string{}
	if raw := strings.TrimSpace(r.FormValue("env")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			writeError(w, http.StatusBadRequest, "env must be a JSON object")
			return
		}
	}
	if err := helper.ValidateInstallEnvironment(env); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	file, header, err := r.FormFile("package")
	if err != nil {
		writeError(w, http.StatusBadRequest, "package file is required")
		return
	}
	defer file.Close()
	format, err := helper.ValidatePackageFilename(header.Filename)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.demo != nil {
		if header.Size > 8<<20 {
			writeError(w, http.StatusRequestEntityTooLarge, "demo package uploads are limited to 8 MiB")
			return
		}
		pkg := &jobPackageSpec{
			Name:   filepath.Base(header.Filename),
			Path:   filepath.Join(s.jobPackageDir(), "demo-"+uuid.NewString()+"."+format),
			SHA256: strings.Repeat("0", 64), Size: 0, Env: env,
		}
		request := jobCreateRequest{Kind: "package-install", HostIDs: hostIDs, Confirm: "install"}
		job, err := s.createJob(s.auditActor(r), request, pkg)
		if err != nil {
			if strings.Contains(err.Error(), "already includes") {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.store.AddAudit(s.auditActor(r), "package-upload", "job", job.ID,
			fmt.Sprintf("demo package=%s", pkg.Name))
		writeJSON(w, http.StatusCreated, map[string]any{"job": jobViewFromStore(job, false)})
		return
	}

	dir := s.jobPackageDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "create package staging directory: "+err.Error())
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "secure package staging directory: "+err.Error())
		return
	}
	tempPath := filepath.Join(dir, uuid.NewString()+"."+format)
	temp, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create package staging file: "+err.Error())
		return
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temp, hasher), io.LimitReader(file, maxPackageUploadSize+1))
	closeErr := temp.Close()
	if copyErr != nil {
		_ = os.Remove(tempPath)
		writeError(w, http.StatusBadRequest, "read package upload: "+copyErr.Error())
		return
	}
	if closeErr != nil {
		_ = os.Remove(tempPath)
		writeError(w, http.StatusInternalServerError, "close package staging file: "+closeErr.Error())
		return
	}
	if written == 0 {
		_ = os.Remove(tempPath)
		writeError(w, http.StatusBadRequest, "package file is empty")
		return
	}
	if written > maxPackageUploadSize {
		_ = os.Remove(tempPath)
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("package exceeds the %d MiB limit", maxPackageUploadSize>>20))
		return
	}
	headerBytes, err := readFileHeader(tempPath, 8)
	if err != nil {
		_ = os.Remove(tempPath)
		writeError(w, http.StatusInternalServerError, "inspect package file: "+err.Error())
		return
	}
	if err := helper.ValidatePackageHeader(format, headerBytes); err != nil {
		_ = os.Remove(tempPath)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pkg := &jobPackageSpec{
		Name: filepath.Base(header.Filename), Path: tempPath,
		SHA256: hex.EncodeToString(hasher.Sum(nil)), Size: written, Env: env,
	}
	request := jobCreateRequest{
		Kind: "package-install", HostIDs: hostIDs, Confirm: "install",
	}
	job, err := s.createJob(s.auditActor(r), request, pkg)
	if err != nil {
		_ = os.Remove(tempPath)
		if strings.Contains(err.Error(), "already includes") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "package-upload", "job", job.ID,
		fmt.Sprintf("package=%s sha256=%s size=%d", pkg.Name, pkg.SHA256, pkg.Size))
	writeJSON(w, http.StatusCreated, map[string]any{"job": jobViewFromStore(job, false)})
}

func readFileHeader(path string, size int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buffer := make([]byte, size)
	n, err := io.ReadFull(file, buffer)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buffer[:n], nil
}

func packageManagerCompatible(host store.Host, filename string) error {
	format, err := helper.ValidatePackageFilename(filename)
	if err != nil {
		return err
	}
	if host.Facts == nil || strings.TrimSpace(host.Facts.PackageManager) == "" {
		return nil
	}
	manager := host.Facts.PackageManager
	switch format {
	case "deb":
		if manager != "apt" {
			return fmt.Errorf("package is .deb but target package manager is %s", manager)
		}
	case "rpm":
		if manager != "dnf" && manager != "zypper" {
			return fmt.Errorf("package is .rpm but target package manager is %s", manager)
		}
	case "pkg.tar.zst":
		if manager != "pacman" {
			return fmt.Errorf("package is .pkg.tar.zst but target package manager is %s", manager)
		}
	case "apk":
		if manager != "apk" {
			return fmt.Errorf("package is .apk but target package manager is %s", manager)
		}
	}
	return nil
}

func (s *Server) removeJobPackage(job store.Job) {
	payload := parseJobPayload(job.Payload)
	if payload.Package == nil || payload.Package.Path == "" {
		return
	}
	dir := filepath.Clean(s.jobPackageDir())
	path := filepath.Clean(payload.Package.Path)
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		slog.Warn("refusing to remove package outside the staging directory", "path", path)
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("remove staged package", "path", path, "error", err)
	}
}

func (s *Server) runPackageInstall(ctx context.Context, host store.Host, pkg *jobPackageSpec) (helper.PackageInstallResult, error) {
	if pkg == nil {
		return helper.PackageInstallResult{}, errors.New("package details are missing")
	}
	if s.demo != nil {
		request := helper.InstallPackageRequest{Filename: pkg.Name, SHA256: pkg.SHA256, Env: pkg.Env}
		body, err := json.Marshal(request)
		if err != nil {
			return helper.PackageInstallResult{}, err
		}
		output, code, err := s.demo.RunHelper(ctx, host, "install-package", string(body), 45*time.Minute)
		if err != nil {
			return helper.PackageInstallResult{}, err
		}
		var result helper.PackageInstallResult
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			return helper.PackageInstallResult{}, fmt.Errorf("demo helper returned invalid install-package JSON: %w", err)
		}
		if code != 0 && result.OK {
			result.OK = false
			result.Error = fmt.Sprintf("helper exited with code %d", code)
		}
		return result, nil
	}
	dir := filepath.Clean(s.jobPackageDir())
	path := filepath.Clean(pkg.Path)
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return helper.PackageInstallResult{}, errors.New("staged package path is outside the job staging directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return helper.PackageInstallResult{}, fmt.Errorf("stat staged package: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return helper.PackageInstallResult{}, errors.New("staged package must not be a symbolic link")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return helper.PackageInstallResult{}, fmt.Errorf("read staged package: %w", err)
	}
	if int64(len(data)) != pkg.Size {
		return helper.PackageInstallResult{}, errors.New("staged package size changed")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), pkg.SHA256) {
		return helper.PackageInstallResult{}, errors.New("staged package SHA-256 does not match the job")
	}
	request := helper.InstallPackageRequest{
		Filename: pkg.Name, SHA256: pkg.SHA256, Env: pkg.Env, Package: data,
	}
	body, err := json.Marshal(request)
	if err != nil {
		return helper.PackageInstallResult{}, err
	}
	output, code, err := s.runHelperInput(ctx, host, "install-package", string(body), 45*time.Minute)
	if err != nil {
		return helper.PackageInstallResult{}, err
	}
	var result helper.PackageInstallResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return helper.PackageInstallResult{}, fmt.Errorf("helper returned invalid install-package JSON: %w (%s)", err, shortRunSummary(output))
	}
	if code != 0 && result.OK {
		result.OK = false
		if result.Error == "" {
			result.Error = fmt.Sprintf("helper exited with code %d", code)
		}
	}
	if result.Error == "" && !result.OK {
		result.Error = "package installation failed"
	}
	return result, nil
}

// runHelperInput invokes a fixed helper action with JSON on stdin. It never
// accepts a sudo password: durable package jobs require the restricted
// NOPASSWD rule, just like scheduled operations.
func (s *Server) runHelperInput(ctx context.Context, host store.Host, action, input string, timeout time.Duration) (string, int, error) {
	if err := s.jobHostRunnable(host); err != nil {
		return "", 0, err
	}
	key, err := s.store.GetHostKey(host.ID)
	if err != nil {
		return "", 0, err
	}
	if key == nil {
		return "", 0, errHostKeyUntrusted
	}
	if s.demo != nil {
		return s.demo.RunHelper(ctx, host, action, input, timeout)
	}
	command := "sudo -n /usr/local/libexec/hibp/hibp-helper " + action
	output, code, err := remote.RunWithInput(ctx, s.hostTarget(host, ""), remoteHostKey(key), command, input, timeout)
	if err != nil {
		return output, code, err
	}
	if code != 0 && looksLikeSudoPasswordInvalid(output) {
		return output, code, errSudoPasswordInvalid
	}
	if code != 0 && looksLikeSudoAuthFailure(output) {
		return output, code, errSudoPasswordRequired
	}
	return output, code, nil
}
