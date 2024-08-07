package ip

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	fireHolURL        = "https://iplists.firehol.org/files/firehol_level1.netset"
	updateInterval    = 12 * time.Hour
	initialRetryDelay = 5 * time.Second
	maxRetryDelay     = 5 * time.Minute
)

var (
	blockedNetworks []*net.IPNet
	networksMutex   sync.RWMutex
)

func StartPeriodicUpdate() {
	go periodicUpdate()
}

func periodicUpdate() {
	retryDelay := initialRetryDelay
	for {
		time.Sleep(updateInterval)
		err := downloadAndParseFireholList()
		if err != nil {
			log.Printf("Failed to update Firehol list: %v", err)
			log.Printf("Will retry in %v", retryDelay)
			time.Sleep(retryDelay)
			retryDelay *= 2
			if retryDelay > maxRetryDelay {
				retryDelay = maxRetryDelay
			}
		} else {
			log.Println("Successfully updated Firehol list")
			retryDelay = initialRetryDelay
		}
	}
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

func IsIPBlocked(ip net.IP) bool {
	networksMutex.RLock()
	defer networksMutex.RUnlock()

	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func InitializeFireholList() error {
	return downloadAndParseFireholList()
}
