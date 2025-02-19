package main

import (
    "flag"
 //   "fmt"
    "strings"
    "log"
)

/*
func ProcessData(input string) string {
    return "Processed:" + input
}
*/

/* 
Handling user input
- Handle command line argument, < 2 -> print enter a PCAP file 
- Provide a file input (using os and pass *File pointer) with -r flags 
- Validate extension of .pcap,.pcapng or .cap
- Trial one: print success
- using log err for err handling since return strings
- Trial two: print filename 
- using flag are arguments 
*/


func handleInput() string {
    pcapfile:=flag.String("r","","Path to a PCAP file (.pcap, .pcapng, .cap)")
    flag.Parse()

    if*pcapfile=="" {
        log.Fatal("Usage: go run . -r <pcapfile>")

    }

    /*
    if len(os.Args) < 2 {
        log.Fatal("Please enter a PCAP file path.")
        return ""
    }
    pcapfile := os.Args[1]
    if valid(pcapfile) {
        fmt.Println("Valid PCAP File:",pcapfile)
    } else {
        fmt.Println("Invalid PCAP File. Please provide a .pcap, .pcapng, or .cap file.")
    }
    */

    if !valid(*pcapfile) {
        log.Fatal("Invalid PCAP File. Please provide a .pcap, .pcapng, or .cap file.")
        return ""
    }
    //fmt.Println("Valid PCAP file: ",*pcapfile)
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



