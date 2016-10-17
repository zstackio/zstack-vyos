package zvr

import (
	"testing"
	"bufio"
	"strings"
	"fmt"
	"unicode/utf8"
	"github.com/pkg/errors"
)

func isSpace(r rune) bool {
	if r <= '\u00FF' {
		// Obvious ASCII ones: \t through \r plus space. Plus two Latin-1 oddballs.
		switch r {
		case ' ', '\t', '\v', '\f', '\r':
			return true
		case '\u0085', '\u00A0':
			return true
		}
		return false
	}
	// High-valued ones.
	if '\u2000' <= r && r <= '\u200a' {
		return true
	}
	switch r {
	case '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000':
		return true
	}
	return false
}

func isSpace1(r byte) bool {
	// Obvious ASCII ones: \t through \r plus space. Plus two Latin-1 oddballs.
	switch r {
	case ' ', '\n', '\t', '\v', '\f', '\r':
		return true
	case '\u0085', '\u00A0':
		return true
	}
	return false
}

func scanWords1(data []byte, atEOF bool) (advance int, token []byte, err error) {
	start := 0
	dataLen := len(data)

	for i := 0; i < dataLen; i ++ {
		w := data[i]
		if w == '\n' || !isSpace1(w) {
			break
		}
		start ++
	}

	for i := start; i < dataLen; i ++ {
		w := data[i]
		if w == '\n' {
			return i+1, data[start:i+1], nil
		}

		if isSpace1(w) {
			return i, data[start:i], nil
		}
	}

	if dataLen > start && atEOF {
		return dataLen, data[start:], nil
	}

	// require more data
	return start, nil, nil
}

func scanWords(data []byte, atEOF bool) (advance int, token []byte, err error) {
	//fmt.Printf("data: %s\n", string(data))
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !isSpace(r) {
			break
		}
	}
	//fmt.Printf("data1: %s\n", string(data))
	// Scan until space, marking end of word.
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if isSpace(r) {
			return i + width, data[start:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	}
	// Request more data.
	return start, nil, nil
}

type role int
const (
	ROOT role = iota
	ROOT_ATTRIBUTE
	KEY_VALUE
	IGNORE
)

func find(words []string) (offset int, role role, key, value string) {
	ws := make([]string, 0)
	next := 0

	// find until \n
	for next = 0; next < len(words); next++ {
		w := words[next]
		if w == "\n" {
			break
		}

		ws = append(ws, w)
	}

	//next ++
	length := len(ws)
	fmt.Printf("xxxxxxxxxxxxxxxxxxxxxxxxx %v %v\n", ws, next)
	if length == 2 && ws[length-1] == "{" {
		return next, ROOT, ws[0], ""
	} else if  length > 2 && ws[length-1] == "{" {
		return next, ROOT_ATTRIBUTE, strings.Join(ws, "."), ""
	} else if length == 2 && ws[length-1] != "{" && ws[length-1] != "}" {
		return next, KEY_VALUE, ws[0], ws[1]
	} else if length == 1 && ws[0] == "}" {
		return next, IGNORE, "", ""
	} else if length == 0 {
		return next+1, IGNORE, "", ""
	} else {
		panic(errors.New(strings.Join(words, " ")))
	}
}

func TestVyosParser(t *testing.T) {
	text := `
	interfaces {
		ethernet eth0 {
		address dhcp
		hw-id 00:0c:29:6a:ef:80
	}
		loopback lo {
	}
	}
	service {
		ssh {
			port 22
		}
	}
	system {
		config-management {
			commit-revisions 20
		}
		console {
		device ttyS0 {
		speed 9600
		}
		}
		login {
		user vyos {
		authentication {
		encrypted-password ****************
		plaintext-password ****************
		}
		level admin
		}
		}
		ntp {
		server 0.pool.ntp.org {
		}
		server 1.pool.ntp.org {
		}
		server 2.pool.ntp.org {
		}
		}
		package {
		repository community {
		components main
		distribution helium
		url http://packages.vyos.net/vyos
		}
		}
		syslog {
		global {
		facility all {
		level notice
		}
		facility protocols {
		level debug
		}
		}
		}
	}
`

	/*
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		advance, token, err = bufio.ScanWords(data, atEOF)
		if err == nil && token != nil {
			//fmt.Println(string(token))
		}
		return
	}
	*/

	words := make([]string, 0)
	for _, s := range strings.Split(text, "\n") {
		scanner := bufio.NewScanner(strings.NewReader(s))
		scanner.Split(bufio.ScanWords)
		ws := make([]string, 0)
		for scanner.Scan() {
			ws = append(ws, scanner.Text())
		}
		ws = append(ws, "\n")
		words = append(words, ws...)
	}

	offset := 0
	for i := 0; i < len(words); i += offset {
		fmt.Printf("yyyyyyyyyyyyyyyyyyyyyyy %v\n", i)
		o, role, key, value := find(words[i:])
		offset = o
		fmt.Printf("offset: %d, role: %d, key: %v, value: %v\n", offset, role, key, value)
	}

	/*
	scanner := bufio.NewScanner(strings.NewReader(text))
	//scanner.Split(split)
	scanner.Split(scanWords)
	words := make([]string, 0)
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}
	for _, w := range words {
		fmt.Printf("word: %s\n", w)
	}
	*/
}
