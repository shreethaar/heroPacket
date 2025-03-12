package analysis

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"io"
	"os"
	"time"
)

type CaptureProperties struct {
	FileName       string   `json:"file_name"`
	FileSize       int64    `json:"file_size"`
	MD5Hash        string   `json:"md5_hash"`
	SHA256Hash     string   `json:"sha256_hash"`
	FirstCaptured  string   `json:"first_captured"`
	LastCaptured   string   `json:"last_captured"`
	InterfacesUsed []string `json:"interfaces_used"`
}

func AnalyzePcap(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return "", err
	}

	md5Hash, sha256Hash, err := computeHashes(file)
	if err != nil {
		return "", err
	}

	interfaces, firstCaptured, lastCaptured, err := parsePcap(filePath)
	if err != nil {
		return "", err
	}

	properties := CaptureProperties{
		FileName:       fileInfo.Name(),
		FileSize:       fileInfo.Size(),
		MD5Hash:        md5Hash,
		SHA256Hash:     sha256Hash,
		FirstCaptured:  firstCaptured,
		LastCaptured:   lastCaptured,
		InterfacesUsed: interfaces,
	}

	jsonData, err := json.MarshalIndent(properties, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func computeHashes(file *os.File) (string, string, error) {
	md5Hash := md5.New()
	sha256Hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(md5Hash, sha256Hash), file); err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%x", md5Hash.Sum(nil)), fmt.Sprintf("%x", sha256Hash.Sum(nil)), nil
}

func parsePcap(filePath string) ([]string, string, string, error) {
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		return nil, "", "", err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var firstTime, lastTime time.Time
	var interfaces []string

	for packet := range packetSource.Packets() {
		if firstTime.IsZero() {
			firstTime = packet.Metadata().Timestamp.UTC()
		}
		lastTime = packet.Metadata().Timestamp.UTC()
	}

	interfaces = append(interfaces, handle.LinkType().String())

	return interfaces, firstTime.Format(time.RFC3339), lastTime.Format(time.RFC3339), nil
}
