package main

import (
    "flag"
 //   "fmt"
    "strings"
    "log"
)

func handleInput() string {
    pcapfile:=flag.String("r","","Path to a PCAP file (.pcap, .pcapng, .cap)")
    flag.Parse()

    if*pcapfile=="" {
        log.Fatal("Usage: go run . -r <pcapfile>")

    }

    if !valid(*pcapfile) {
        log.Fatal("Invalid PCAP File. Please provide a .pcap, .pcapng, or .cap file.")
        return ""
    }
    return *pcapfile
}
    
func valid(filename string) bool {
    validExtensions:=[]string{".pcap",".pcapng",".cap"}
    for _,ext:=range validExtensions {
        if strings.HasSuffix(strings.ToLower(filename),ext) {
            return true
        }
    }
    return false
}



