package main

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/scmmishra/ipshield/internal/ip"
)

const (
	fireHolURL        = "https://iplists.firehol.org/files/firehol_level1.netset"
	torExitNodeURL    = "https://check.torproject.org/torbulkexitlist"
	updateInterval    = 6 * time.Hour
	initialRetryDelay = 5 * time.Second
	maxRetryDelay     = 5 * time.Minute
	cacheTTL          = 3600 // 1 hour in seconds
)

var (
	blockedNetworks    []*net.IPNet
	dataCenterNetworks []*net.IPNet
	torExitNodes       []net.IP
	networksMutex      sync.RWMutex
)

func main() {
	err := downloadAndParseFireholList()
	if err != nil {
		log.Printf("Failed to download and parse Firehol list: %v", err)
		log.Println("Starting with an empty list. Will retry in the background.")
	}

	err = downloadAndParseTorExitNodes()
	if err != nil {
		log.Printf("Failed to download and parse Tor exit node list: %v", err)
		log.Println("Starting with an empty Tor exit node list. Will retry in the background.")
	}

	// Download data center IP ranges
	dataCenterRanges, err := ip.GetDataCenterIPRanges()
	if err != nil {
		log.Printf("Warning: Error fetching some data center ranges: %v", err)
	}
	dataCenterNetworks = dataCenterRanges

	// Start the periodic update goroutine
	go periodicUpdate()

	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Printf("Starting DNS server on port 53")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n", err.Error())
	}
}

func periodicUpdate() {
	retryDelay := initialRetryDelay
	for {
		time.Sleep(updateInterval)

		if err := downloadAndParseFireholList(); err != nil {
			log.Printf("Failed to update Firehol list: %v", err)
			retryDelay = handleUpdateError(retryDelay)
		} else {
			log.Println("Successfully updated Firehol list")
			retryDelay = initialRetryDelay
		}

		if err := downloadAndParseTorExitNodes(); err != nil {
			log.Printf("Failed to update Tor exit node list: %v", err)
			retryDelay = handleUpdateError(retryDelay)
		} else {
			log.Println("Successfully updated Tor exit node list")
			retryDelay = initialRetryDelay
		}

		// Update data center IP ranges
		dataCenterRanges, err := ip.GetDataCenterIPRanges()
		if err != nil {
			log.Printf("Warning: Error updating data center ranges: %v", err)
			retryDelay = handleUpdateError(retryDelay)
		} else {
			networksMutex.Lock()
			dataCenterNetworks = dataCenterRanges
			networksMutex.Unlock()
			log.Println("Successfully updated data center IP ranges")
			retryDelay = initialRetryDelay
		}
	}
}

func handleUpdateError(retryDelay time.Duration) time.Duration {
	log.Printf("Will retry in %v", retryDelay)
	time.Sleep(retryDelay)
	retryDelay *= 2
	if retryDelay > maxRetryDelay {
		retryDelay = maxRetryDelay
	}
	return retryDelay
}

func downloadAndParseFireholList() error {
	resp, err := http.Get(fireHolURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var newBlockedNetworks []*net.IPNet

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
		newBlockedNetworks = append(newBlockedNetworks, ipNet)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// the mutex will ensure that the DNS handler doesn't read the list while it's being updated
	networksMutex.Lock()
	blockedNetworks = newBlockedNetworks
	networksMutex.Unlock()

	log.Printf("Loaded %d blocked networks", len(newBlockedNetworks))
	return nil
}

func isTorExitNode(ip net.IP) bool {
	networksMutex.RLock()
	defer networksMutex.RUnlock()

	for _, exitNode := range torExitNodes {
		if exitNode.Equal(ip) {
			return true
		}
	}
	return false
}

func downloadAndParseTorExitNodes() error {
	resp, err := http.Get(torExitNodeURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var newTorExitNodes []net.IP

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip := net.ParseIP(line)
		if ip == nil {
			log.Printf("Error parsing IP %s", line)
			continue
		}
		newTorExitNodes = append(newTorExitNodes, ip)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	networksMutex.Lock()
	torExitNodes = newTorExitNodes
	networksMutex.Unlock()

	log.Printf("Loaded %d Tor exit nodes", len(newTorExitNodes))
	return nil
}

func isIPBlocked(ip net.IP) bool {
	// Acquire a read lock to safely access blockedNetworks
	networksMutex.RLock()
	defer networksMutex.RUnlock()

	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isDataCenterIP(ip net.IP) bool {
	networksMutex.RLock()
	defer networksMutex.RUnlock()

	for _, network := range dataCenterNetworks {
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
			case dns.TypeTXT:
				name := strings.TrimSuffix(q.Name, ".")
				ip := net.ParseIP(name)

				if ip == nil {
					continue
				}

				var txt string
				if isIPBlocked(ip) {
					txt = "FLAGGED"
				} else if isDataCenterIP(ip) {
					txt = "DATACENTER"
				} else if isTorExitNode(ip) {
					txt = "TOR_EXIT"
				} else {
					txt = "SAFE"
				}

				rr := &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: cacheTTL},
					Txt: []string{txt},
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}

	w.WriteMsg(m)
}
