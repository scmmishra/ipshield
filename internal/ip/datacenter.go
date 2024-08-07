package ip

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	datacenterIPRangesURL = "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt"
	ociCIDRURL            = "https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
	doCIDRURL             = "https://www.digitalocean.com/geo/google.csv"
)

func GetDataCenterIPRanges() ([]*net.IPNet, error) {
	var allRanges []*net.IPNet
	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, 3) // Buffer for potential errors

	// Helper function to add IP ranges
	addRanges := func(ranges []*net.IPNet) {
		mu.Lock()
		allRanges = append(allRanges, ranges...)
		mu.Unlock()
	}

	// Main datacenter ranges
	wg.Add(1)
	go func() {
		defer wg.Done()
		ranges, err := getMainDatacenterRanges()
		if err != nil {
			errChan <- fmt.Errorf("main datacenter ranges: %w", err)
			return
		}
		addRanges(ranges)
	}()

	// OCI ranges
	wg.Add(1)
	go func() {
		defer wg.Done()
		ranges, err := getOCIRanges()
		if err != nil {
			errChan <- fmt.Errorf("OCI: %w", err)
			return
		}
		addRanges(ranges)
	}()

	// DigitalOcean ranges
	wg.Add(1)
	go func() {
		defer wg.Done()
		ranges, err := getDORanges()
		if err != nil {
			errChan <- fmt.Errorf("DigitalOcean: %w", err)
			return
		}
		addRanges(ranges)
	}()

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errStrings []string
	for err := range errChan {
		errStrings = append(errStrings, err.Error())
	}

	if len(errStrings) > 0 {
		return allRanges, fmt.Errorf("errors occurred: %s", strings.Join(errStrings, "; "))
	}

	return allRanges, nil
}

func getMainDatacenterRanges() ([]*net.IPNet, error) {
	resp, err := http.Get(datacenterIPRangesURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch main datacenter IP ranges: %w", err)
	}
	defer resp.Body.Close()

	return parseIPRanges(resp.Body)
}

func getOCIRanges() ([]*net.IPNet, error) {
	resp, err := http.Get(ociCIDRURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCI IP ranges: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Regions []struct {
			Region string `json:"region"`
			Cidrs  []struct {
				Cidr string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse OCI IP ranges JSON: %w", err)
	}

	var ranges []string
	for _, region := range data.Regions {
		for _, cidr := range region.Cidrs {
			ranges = append(ranges, cidr.Cidr)
		}
	}

	return parseIPRanges(strings.NewReader(strings.Join(ranges, "\n")))
}

func getDORanges() ([]*net.IPNet, error) {
	resp, err := http.Get(doCIDRURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DigitalOcean IP ranges: %w", err)
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	var ranges []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading DigitalOcean CSV: %w", err)
		}
		if len(record) > 0 {
			ranges = append(ranges, record[0])
		}
	}

	return parseIPRanges(strings.NewReader(strings.Join(ranges, "\n")))
}

func parseIPRanges(r io.Reader) ([]*net.IPNet, error) {
	var ipNets []*net.IPNet
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		cidr := strings.TrimSpace(scanner.Text())
		if cidr == "" {
			continue
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Log the error but continue processing
			fmt.Printf("Error parsing CIDR %s: %v\n", cidr, err)
			continue
		}
		ipNets = append(ipNets, ipNet)
	}

	if err := scanner.Err(); err != nil {
		return ipNets, fmt.Errorf("error reading IP ranges: %w", err)
	}

	return ipNets, nil
}
