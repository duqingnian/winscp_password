package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

const (
	PW_MAGIC = 0xA3
	PW_FLAG  = 0xFF
)

type RandomOption struct {
	Length        int
	UseLowercase  bool
	UseUppercase  bool
	UseDigits     bool
	UseSymbols    bool
	ExtraChars    string
}

func encByte(b byte) string {
	enc := ^(b ^ PW_MAGIC) & 0xFF
	return fmt.Sprintf("%02X", enc)
}

func decNextChar(s *string) byte {
	if len(*s) < 2 {
		return 0
	}
	base := "0123456789ABCDEF"
	a := strings.IndexByte(base, (*s)[0])
	b := strings.IndexByte(base, (*s)[1])
	*s = (*s)[2:]
	return byte(^(byte((a<<4)+b) ^ PW_MAGIC))
}

func encrypt(password, key string) string {
	full := key + password
	var result strings.Builder

	result.WriteString(encByte(PW_FLAG))  // flag
	result.WriteString(encByte(0))        // dummy
	result.WriteString(encByte(byte(len(full)))) // length
	result.WriteString(encByte(0))        // offset = 0

	for i := 0; i < len(full); i++ {
		result.WriteString(encByte(full[i]))
	}
	return result.String()
}

func decrypt(pwd string, key string) string {
	var clear strings.Builder

	flag := decNextChar(&pwd)
	var length byte

	if flag == PW_FLAG {
		_ = decNextChar(&pwd) // dummy
		length = decNextChar(&pwd)
	} else {
		length = flag
	}

	offset := decNextChar(&pwd)
	pwd = pwd[int(offset)*2:]

	for i := 0; i < int(length); i++ {
		clear.WriteByte(decNextChar(&pwd))
	}

	result := clear.String()
	if flag == PW_FLAG {
		if !strings.HasPrefix(result, key) {
			return ""
		}
		result = result[len(key):]
	}
	return result
}

func generateRandom(opt RandomOption) string {
	charset := ""
	if opt.UseLowercase {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if opt.UseUppercase {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if opt.UseDigits {
		charset += "0123456789"
	}
	if opt.UseSymbols {
		charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
	}
	charset += opt.ExtraChars

	rand.Seed(time.Now().UnixNano())
	result := make([]byte, opt.Length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func formatNow(t time.Time) string {
	return t.Format("2006-01-02 15:04:05.000")
}

func formatDuration(ms int64) string {
	return fmt.Sprintf("%ds%dms", ms/1000, ms%1000)
}

func main() {
	user := "root"
	host := "192.168.12.34"
	key := user + host

	opt := RandomOption{
		Length:       64,
		UseLowercase: true,
		UseUppercase: true,
		UseDigits:    true,
		UseSymbols:   true,
		ExtraChars:   "#~-_",
	}

	matchCount := 0
	mismatchCount := 0
	loopCount := 100

	start := time.Now()
	fmt.Println("Start Time    :", formatNow(start))

	for i := 1; i <= loopCount; i++ {
		password := generateRandom(opt)
		crypted := encrypt(password, key)
		plain := decrypt(crypted, key)
		match := password == plain
		if match {
			matchCount++
		} else {
			mismatchCount++
		}

		fmt.Printf("===== Test #%d =====\n", i)
		fmt.Println("Plain     :", password)
		fmt.Println("Encrypted :", crypted)
		fmt.Println("Decrypted :", plain)
		fmt.Println("Match     :", map[bool]string{true: "......Yes", false: "......No"}[match])
		fmt.Println()
		time.Sleep(100 * time.Millisecond)
	}

	end := time.Now()
	duration := end.Sub(start).Milliseconds()

	fmt.Println("End Time      :", formatNow(end))
	fmt.Println("Total Duration:", formatDuration(duration))
	fmt.Println("Match Count   :", matchCount)
	fmt.Println("Mismatch Count:", mismatchCount)
}
