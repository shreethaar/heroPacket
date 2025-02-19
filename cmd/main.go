package main

import (
    "fmt"
)

func main() {
    //result:=ProcessData("some data")
    //fmt.Println(result)
    //handleInput()
    pcap:=handleInput()
    readerPcap(pcap) 
}

func readerPcap(filePath string) {
    fmt.Println("TEST readerPcap function") // implementation at internal/pcap/reader.go

}
