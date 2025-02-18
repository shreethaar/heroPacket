package main

import (
  //  "flag"
    "fmt"
    "os"
    "strings"
 //   "path"
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
*/





func handleInput() {
    if len(os.Args) < 2 {
        fmt.Println("Please enter a PCAP file path.")
        return 
    }
    pcapfile := os.Args[1]
    if valid(pcapfile) {
        fmt.Println("Valid PCAP File:",pcapfile)
    } else {
        fmt.Println("Invalid PCAP File. Please provide a .pcap, .pcapng, or .cap file.")
    }
}

 //   fmt.Println("PCAP file: ",pcapfile)
   
func valid(filename string) bool {
    validExtensions:=[]string{".pcap",".pcapng",".cap"}
    for _,ext:=range validExtensions {
        if strings.HasSuffix(strings.ToLower(filename),ext) {
            return true
        }
    }
    return false
}



