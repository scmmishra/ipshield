package main

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

var blockedIPs = map[string]bool{
	"8.8.8.8": true,
	"1.1.1.1": true,
}

func main() {
	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Printf("Starting DNS server on port 53")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n", err.Error())
	}
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode == dns.OpcodeQuery {
		for _, q := range m.Question {
			switch q.Qtype {
			case dns.TypeA:
				ip := strings.TrimSuffix(q.Name, ".")
				if blockedIPs[ip] {
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
