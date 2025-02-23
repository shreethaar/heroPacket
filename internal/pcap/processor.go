package pcap

import (
    "io"
    "log"
    "os"
)

func ProcessFile(filename string, file io.Reader) {
    // Create a new file in the server
    dst, err := os.Create("/tmp/" + filename)
    if err != nil {
        log.Fatal(err)
    }
    defer dst.Close()

    // Copy the uploaded file's content to the new file
    if _, err := io.Copy(dst, file); err != nil {
        log.Fatal(err)
    }

    // Here you can add more logic to process the PCAP file
    log.Printf("File %s uploaded and saved", filename)
}
