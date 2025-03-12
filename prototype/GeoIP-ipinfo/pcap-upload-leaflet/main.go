package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	IPINFO_TOKEN   = "IPINFO_TOKEN" // Replace with your token
	UPLOAD_DIR     = "uploads"
	STATIC_DIR     = "static"
	MAX_UPLOAD_SIZE = 10 << 20 // 10MB limit
)

// IPInfo struct for API response
type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Loc     string `json:"loc"`
	Org     string `json:"org"`
}

// Ensure upload directory exists
func init() {
	if _, err := os.Stat(UPLOAD_DIR); os.IsNotExist(err) {
		os.Mkdir(UPLOAD_DIR, 0755)
	}
}

// Function to check if an IP is private
func isPrivateIP(ip string) bool {
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

// Function to extract unique public IPs from a PCAP file
func extractPublicIPs(pcapFile string) map[string]struct{} {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil
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

		if !isPrivateIP(srcIP) {
			publicIPs[srcIP] = struct{}{}
		}
		if !isPrivateIP(dstIP) {
			publicIPs[dstIP] = struct{}{}
		}
	}
	return publicIPs
}

// Function to fetch geolocation data
func getIPInfo(ip string) (*IPInfo, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, IPINFO_TOKEN)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ipData IPInfo
	if err := json.Unmarshal(body, &ipData); err != nil {
		return nil, err
	}

	return &ipData, nil
}

// HTTP handler to process PCAP file uploads
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MAX_UPLOAD_SIZE)
	err := r.ParseMultipartForm(MAX_UPLOAD_SIZE)
	if err != nil {
		http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}

	file, handler, err := r.FormFile("pcap")
	if err != nil {
		http.Error(w, "Failed to read uploaded file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save file
	filePath := filepath.Join(UPLOAD_DIR, handler.Filename)
	outFile, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()
	io.Copy(outFile, file)

	// Process PCAP file
	publicIPs := extractPublicIPs(filePath)
	if len(publicIPs) == 0 {
		http.Error(w, "No public IPs found", http.StatusNoContent)
		return
	}

	// Fetch geolocation data
	results := []IPInfo{}
	for ip := range publicIPs {
		info, err := getIPInfo(ip)
		if err != nil {
			continue
		}
		results = append(results, *info)
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// HTTP handler to serve static files (index.html, CSS, JS)
func staticHandler() http.Handler {
	return http.StripPrefix("/", http.FileServer(http.Dir(STATIC_DIR)))
}

func main() {
	http.Handle("/", staticHandler())         // Serve index.html
	http.HandleFunc("/upload", uploadHandler) // Handle PCAP uploads

	fmt.Println("Server running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}
