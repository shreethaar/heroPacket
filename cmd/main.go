package main

import (
    "fmt"
    "log"
    localpcap"heroPacket/internal/pcap"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

func main() {
    pcap:=handleInput()
    if pcap == "" {
        log.Fatal("No valid PCAP File provided.")
    }
    readerPcap(pcap)
}

func readerPcap(filePath string) {
    fmt.Println("Processing PCAP file:", filePath)
    handle, err := pcap.OpenOffline(filePath)
    if err != nil {
        log.Fatalf("Error opening PCAP: %v", err)
    }
    defer handle.Close()
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    fmt.Println("Starting packet processing...")
    for packet := range packetSource.Packets() {
        localpcap.ProcessPacket(packet)
    }
    
    fmt.Println("\nPacket processing complete!")
}
