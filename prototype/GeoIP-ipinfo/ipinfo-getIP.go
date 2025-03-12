package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    //"os"
)

const IPINFO_TOKEN = "ip-info-token-here"

type IPInfo struct {
    IP string `json:"ip"`
    City string `json:"city"`
    Region string `json:"region"`
    Country string `json:"country"`
    Loc string `json:"loc"`
    Org string `json:"org"`
}

func getIPInfo(ip string) (*IPInfo, error) {
    url:=fmt.Sprintf("https://ipinfo.io/%s/json?token=%s",ip,IPINFO_TOKEN)
    resp,err:=http.Get(url)
    if err!=nil {
        return nil,err
    }
    defer resp.Body.Close()

    body,_:=io.ReadAll(resp.Body)

    var ipData IPInfo 
    err=json.Unmarshal(body,&ipData)
    if err!=nil {
        return nil,err
    }
    return &ipData,nil
}

func main() {
    ips:=[]string{"8.8.8.8","1.1.1.1","128.101.101.101"}
    for _,ip:=range ips {
        info,err:=getIPInfo(ip) 
        if err!=nil {
            fmt.Println("Error fetching IP info:",err) 
            continue
        }
        fmt.Printf("IP: %s | City: %s | Region: %s | Country: %s | Loc: %s | ISP: %s\n", info.IP, info.City, info.Region, info.Country, info.Loc, info.Org) 
    }
}
