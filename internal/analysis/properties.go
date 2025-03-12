package analysis

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type CaptureProperties struct {
	FileName     string    `json:"file_name"`
	FileSize     int64     `json:"file_size"`
	MD5Hash      string    `json:"md5_hash"`
	SHA256Hash   string    `json:"sha256_hash"`
	FirstPacket  time.Time `json:"first_packet_utc"`
	LastPacket   time.Time `json:"last_packet_utc"`
	Interfaces   []string  `json:"interfaces"`
}

func ComputeHashes(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(md5Hash, file)
		wg.Done()
	}()

	file.Seek(0, 0) // Reset file pointer for the second hash computation

	go func() {
		io.Copy(sha256Hash, file)
		wg.Done()
	}()

	wg.Wait()

	md5Str := hex.EncodeToString(md5Hash.Sum(nil))
	sha256Str := hex.EncodeToString(sha256Hash.Sum(nil))

	return md5Str, sha256Str, nil
}

func GetCaptureProperties(filePath string) (string, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}

	md5Hash, sha256Hash, err := ComputeHashes(filePath)
	if err != nil {
		return "", err
	}

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	firstPacketTime, lastPacketTime := time.Time{}, time.Time{}
	interfaces := []string{handle.LinkType().String()}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if firstPacketTime.IsZero() {
			firstPacketTime = packet.Metadata().Timestamp.UTC()
		}
		lastPacketTime = packet.Metadata().Timestamp.UTC()
	}

	captureProps := CaptureProperties{
		FileName:    fileInfo.Name(),
		FileSize:    fileInfo.Size(),
		MD5Hash:     md5Hash,
		SHA256Hash:  sha256Hash,
		FirstPacket: firstPacketTime,
		LastPacket:  lastPacketTime,
		Interfaces:  interfaces,
	}

	jsonData, err := json.MarshalIndent(captureProps, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}
