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
	ipsumURL          = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
	greensnowURL      = "https://blocklist.greensnow.co/greensnow.txt"
	updateInterval    = 6 * time.Hour
	initialRetryDelay = 5 * time.Second
	maxRetryDelay     = 5 * time.Minute
	cacheTTL          = 3600 // 1 hour in seconds
)

var (
	blockedNetworks    []*net.IPNet
	dataCenterNetworks []*net.IPNet
	torExitNodes       []net.IP
	ipsumIPs           []net.IP
	greensnowIPs       []net.IP
	networksMutex      sync.RWMutex
)

func main() {
	if err := downloadAndParseFireholList(); err != nil {
		log.Printf("Failed to download and parse Firehol list: %v", err)
		log.Println("Starting with an empty list. Will retry in the background.")
	}

	if err := downloadAndParseTorExitNodes(); err != nil {
		log.Printf("Failed to download and parse Tor exit node list: %v", err)
		log.Println("Starting with an empty Tor exit node list. Will retry in the background.")
	}

	if err := downloadAndParseIpsumList(); err != nil {
		log.Printf("Failed to download and parse IPsum list: %v", err)
		log.Println("Starting with an empty IPsum list. Will retry in the background.")
	}

	if err := downloadAndParseGreensnowList(); err != nil {
		log.Printf("Failed to download and parse Greensnow list: %v", err)
		log.Println("Starting with an empty Greensnow list. Will retry in the background.")
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

		updateFunctions := []struct {
			name string
			fn   func() error
		}{
			{"Firehol list", downloadAndParseFireholList},
			{"Tor exit node list", downloadAndParseTorExitNodes},
			{"IPsum list", downloadAndParseIpsumList},
			{"Greensnow list", downloadAndParseGreensnowList},
		}

		for _, update := range updateFunctions {
			if err := update.fn(); err != nil {
				log.Printf("Failed to update %s: %v", update.name, err)
				retryDelay = handleUpdateError(retryDelay)
			} else {
				log.Printf("Successfully updated %s", update.name)
				retryDelay = initialRetryDelay
			}
		}

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

	networksMutex.Lock()
	blockedNetworks = newBlockedNetworks
	networksMutex.Unlock()

	log.Printf("Loaded %d blocked networks", len(newBlockedNetworks))
	return nil
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

func downloadAndParseIpsumList() error {
	resp, err := http.Get(ipsumURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var newIpsumIPs []net.IP

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			log.Printf("Error parsing IP %s", fields[0])
			continue
		}
		newIpsumIPs = append(newIpsumIPs, ip)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	networksMutex.Lock()
	ipsumIPs = newIpsumIPs
	networksMutex.Unlock()

	log.Printf("Loaded %d IPsum IPs", len(newIpsumIPs))
	return nil
}

func downloadAndParseGreensnowList() error {
	resp, err := http.Get(greensnowURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var newGreensnowIPs []net.IP

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
		newGreensnowIPs = append(newGreensnowIPs, ip)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	networksMutex.Lock()
	greensnowIPs = newGreensnowIPs
	networksMutex.Unlock()

	log.Printf("Loaded %d Greensnow IPs", len(newGreensnowIPs))
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

func isIPBlocked(ip net.IP) bool {
	networksMutex.RLock()
	defer networksMutex.RUnlock()

	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	for _, blockedIP := range ipsumIPs {
		if ip.Equal(blockedIP) {
			return true
		}
	}

	for _, blockedIP := range greensnowIPs {
		if ip.Equal(blockedIP) {
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
