package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const IPINFO_TOKEN = ""

// IPInfo struct for API response
type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Loc     string `json:"loc"`
	Org     string `json:"org"`
}

// IsPrivateIP checks if an IP address is private
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateCIDRs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
	}

	for _, cidr := range privateCIDRs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// ExtractPublicIPs extracts unique public IPs from a PCAP file
func ExtractPublicIPs(pcapFile string) (map[string]struct{}, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	publicIPs := make(map[string]struct{})
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		srcIP := networkLayer.NetworkFlow().Src().String()
		dstIP := networkLayer.NetworkFlow().Dst().String()

		if !IsPrivateIP(srcIP) {
			publicIPs[srcIP] = struct{}{}
		}
		if !IsPrivateIP(dstIP) {
			publicIPs[dstIP] = struct{}{}
		}
	}
	return publicIPs, nil
}

// GetIPInfo fetches geolocation data for an IP using the ipinfo.io API
func GetIPInfo(ip string) (*IPInfo, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, IPINFO_TOKEN)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching IP info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading API response: %v", err)
	}

	var ipData IPInfo
	if err := json.Unmarshal(body, &ipData); err != nil {
		return nil, fmt.Errorf("error unmarshaling API response: %v", err)
	}

	return &ipData, nil
}

// ProcessPCAPAndFetchGeoInfo processes a PCAP file and fetches geolocation data for public IPs
func ProcessPCAPAndFetchGeoInfo(pcapFile string) ([]IPInfo, error) {
	publicIPs, err := ExtractPublicIPs(pcapFile)
	if err != nil {
		return nil, err
	}

	if len(publicIPs) == 0 {
		return nil, fmt.Errorf("no public IPs found in PCAP file")
	}

	results := []IPInfo{}
	for ip := range publicIPs {
		info, err := GetIPInfo(ip)
		if err != nil {
			continue // Skip IPs that fail to fetch geolocation data
		}
		results = append(results, *info)
	}

	return results, nil
}




