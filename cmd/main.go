package main

import (
//    "fmt"
    "log"
//    localpcap"heroPacket/internal/pcap"
//    "github.com/google/gopacket"
//    "github.com/google/gopacket/pcap"
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "heroPacket/internal/handlers"
)

func main() {
    /*
    pcap:=handleInput()
    if pcap == "" {
        log.Fatal("No valid PCAP File provided.")
    }
    readerPcap(pcap)
    */
    r:=chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("internal/static"))))

    r.Get("/",handlers.Home)
    r.Post("/upload",handlers.UploadPCAP)
    r.Get("/status/{id}", handlers.GetStatus)
    r.Get("/results/{id}", handlers.GetResults)

    /*
    r.Get("/analysis/{id}",handlers.ShowAnalysis)
    r.Get("/analysis/{id}/stats",handlers.GetStats)
    r.Get("/analysis/{id}/packets",handlers.GetPackets)
    */

    log.Println("Server starting on :3000")
    http.ListenAndServe(":3000",r)
}
/*
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
        metadata,details:=localpcap.ExtractPacketInfo(packet) 
        if details.NetworkLayer.Protocol=="UDP" {
            fmt.Println(metadata)
            if dnsInfo:=localpcap.ExtractDNSInfo(packet);dnsInfo!=nil {
                fmt.Println("process dns info")
                }
            }
    }
    
    fmt.Println("\nPacket processing complete!")
}
*/

/* Reason for comment the rest of the function because I am starting to implement chi for routing and essentially main.go's purpose is to serve web app 
*/
