package main

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

const fireHolURL = "https://iplists.firehol.org/files/firehol_level1.netset"

var blockedNetworks []*net.IPNet

func main() {
	err := downloadAndParseFireholList()
	if err != nil {
		log.Fatalf("Failed to download and parse Firehol list: %v", err)
	}

	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Printf("Starting DNS server on port 53")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n", err.Error())
	}
}

func downloadAndParseFireholList() error {
	resp, err := http.Get(fireHolURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("Error parsing CIDR %s: %v", line, err)
			continue
		}
		blockedNetworks = append(blockedNetworks, ipNet)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	log.Printf("Loaded %d blocked networks", len(blockedNetworks))
	return nil
}

func isIPBlocked(ip net.IP) bool {
	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode == dns.OpcodeQuery {
		for _, q := range m.Question {
			switch q.Qtype {
			case dns.TypeA:
				ip := net.ParseIP(strings.TrimSuffix(q.Name, "."))
				if ip == nil {
					continue
				}
				if isIPBlocked(ip) {
					rr, err := dns.NewRR(q.Name + " A 127.0.0.2")
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				} else {
					rr, err := dns.NewRR(q.Name + " A 127.0.0.1")
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		}
	}

	w.WriteMsg(m)
}
