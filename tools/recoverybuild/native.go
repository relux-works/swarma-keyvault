package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/nativebuild"
)

// This source-build operation has no signing/inspection/custody branch. Default
// recovery releases still use build and its existing clean-source/signing order.
func buildNativeHelper(out string) error {
	if runtime.GOOS != "darwin" || runtime.Version() != "go1.26.10" {
		return errors.New("requires macOS and the exact Go version pinned by go.mod")
	}
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return errors.New("a new absolute output directory is required")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if err = os.Mkdir(filepath.Join(root, ".temp"), 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if err := os.Mkdir(out, 0700); err != nil {
		return errors.New("output directory must not already exist")
	}
	log, err := os.OpenFile(filepath.Join(out, "build.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := nativebuild.Build(ctx, nativebuild.Options{Root: root, GoTool: filepath.Join(runtime.GOROOT(), "bin", "go"), Log: log})
	if err != nil {
		return err
	}
	helper := filepath.Join(out, "mac-keyvault-enclave")
	if err = nativebuild.CopyHelper(result, helper); err != nil {
		return err
	}
	if err = nativebuild.WriteReceipt(result, filepath.Join(out, "native-build-receipt.json")); err != nil {
		return err
	}
	fmt.Println(helper)
	return nil
}
