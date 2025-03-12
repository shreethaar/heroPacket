// Parse PCAP -> extract source and destination ip 
// Filters private IP -> keeps only public IP
// Fetchs IP Geolocation -> uses IPInfo API
// Prints results -> IP, City, Country, Lat/Long, ISP
// Supports both IPv4 and IPv6

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)


type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Loc     string `json:"loc"`
	Org     string `json:"org"`
}

const IPINFO_TOKEN = "ip-info-token" 


func isReservedIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Define reserved IP ranges
	reservedCIDRs := []string{
		"0.0.0.0/8",       // Unspecified
		"255.255.255.255/32", // Broadcast
		"224.0.0.0/4",     // IPv4 Multicast
		"::/128",          // IPv6 Unspecified
		"ff00::/8",        // IPv6 Multicast
	}

	for _, cidr := range reservedCIDRs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",   
        "fe80::/10",  
		"::1/128",    
		"ff00::/8",   
	}

	for _, cidr := range privateCIDRs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func extractPublicIPs(pcapFile string) map[string]bool {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil
	}
	defer handle.Close()

	publicIPs := make(map[string]bool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		srcIP := networkLayer.NetworkFlow().Src().String()
		dstIP := networkLayer.NetworkFlow().Dst().String()

    
        if net.ParseIP(srcIP) != nil && !isPrivateIP(srcIP) && !isReservedIP(srcIP) {
	        publicIPs[srcIP] = true
        }
        if net.ParseIP(dstIP) != nil && !isPrivateIP(dstIP) && !isReservedIP(dstIP) {
	        publicIPs[dstIP] = true
        }

    }

	return publicIPs
}


func getIPInfo(ip string) (*IPInfo, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, IPINFO_TOKEN)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body) 

	var ipData IPInfo
	err = json.Unmarshal(body, &ipData)
	if err != nil {
		return nil, err
	}

	return &ipData, nil
}

func main() {
	pcapFile := "ENTER PCAP HERE"

	publicIPs := extractPublicIPs(pcapFile)
	if publicIPs == nil {
		fmt.Println("No public IPs found.")
		return
	}

	fmt.Println("Fetching geolocation data for public IPs...")
	for ip := range publicIPs {
		info, err := getIPInfo(ip)
		if err != nil {
			fmt.Println("Error fetching IP info for", ip, ":", err)
			continue
		}

		fmt.Printf("IP: %s | City: %s | Region: %s | Country: %s | Location: %s | ISP: %s\n",
			info.IP, info.City, info.Region, info.Country, info.Loc, info.Org)
	}
}
