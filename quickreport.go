package quickreport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	blacklisted  string = "blacklisted"
	clean        string = "clean"
	malwareFound string = "malwarefound"
)

var (
	errMalformedLine = errors.New("Unable to parse line")
	errReadFailed    = errors.New("Unable to open file")
)

// Clobber is for overwriting previously read data
var Clobber bool

// Result contains a count of blacklisted, clean, or malware flagged websites.
type Result struct{ Blacklisted, NoIssuesFound, MalwareDetected int }
type status struct{ isBlacklisted, isMalwareFound bool }

// New reads from a file and returns a Result.
func New(s string, c bool) (Result, error) {
	Clobber = c
	report := new(Result)
	f, err := os.Open(s)
	if err != nil {
		return Result{}, err
	}
	r, err := report.parse(bufio.NewReader(f))
	if err != nil {
		return r, err
	}
	f.Close()
	return r, nil
}

func (report Result) parse(r io.Reader) (Result, error) {
	sites := make(map[string]status)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		split := strings.Fields(scanner.Text())
		site := split[0]
		if len(split) != 3 {
			return Result{}, fmt.Errorf("%s: %s", errMalformedLine, scanner.Text())
		}
		isBlacklisted, err := state(split[1])
		if err != nil {
			return Result{}, fmt.Errorf("%s: %s", errMalformedLine, err)
		}
		isMalwareFound, err := state(split[2])
		if err != nil {
			return Result{}, fmt.Errorf("%s: %s", errMalformedLine, err)
		}
		if isMalwareFound {
			report.MalwareDetected++
		}
		if Clobber {
			// Check for duplicate sites in the map and preserve their previous results
			if prevResult, found := sites[site]; found {
				if isBlacklisted {
					//					log.Printf("DEBUG blacklisted++ len: %d, DUMPING: %s blacklisted: %v, malwaredetected: %v", len(sites), site, isBlacklisted, isMalwareFound)
					sites[site] = status{isBlacklisted: isBlacklisted, isMalwareFound: prevResult.isMalwareFound}
				} else if isMalwareFound {
					//					log.Printf("DEBUG malwarefound++ len: %d, DUMPING: %s blacklisted: %v, malwaredetected: %v", len(sites), site, isBlacklisted, isMalwareFound)
					sites[site] = status{isBlacklisted: prevResult.isBlacklisted, isMalwareFound: isMalwareFound}
				}
			} else {
				// Found a new site to add to the map
				if isBlacklisted {
					//					log.Printf("DEBUG blacklisted++ len: %d, DUMPING: %s blacklisted: %v, malwaredetected: %v", len(sites), site, isBlacklisted, isMalwareFound)
					sites[site] = status{isBlacklisted: isBlacklisted, isMalwareFound: prevResult.isMalwareFound}
				} else if isMalwareFound {
					//					log.Printf("DEBUG malwarefound++ len: %d, DUMPING: %s blacklisted: %v, malwaredetected: %v", len(sites), site, isBlacklisted, isMalwareFound)
					sites[site] = status{isBlacklisted: prevResult.isBlacklisted, isMalwareFound: isMalwareFound}
				}
				sites[site] = status{isBlacklisted: isBlacklisted, isMalwareFound: isMalwareFound}
				//				log.Printf("DEBUG cleanclean++ len: %d, DUMPING: %s blacklisted: %v, malwaredetected: %v", len(sites), site, isBlacklisted, isMalwareFound)
			}
		} else {
			// Clobber and intentionally overwrite previous items in the map
			sites[site] = status{isBlacklisted: isBlacklisted, isMalwareFound: isMalwareFound}
		}
		if err := scanner.Err(); err != nil {
			return report, fmt.Errorf("%s: %s", errMalformedLine, err)
		}
	}
	// Actually compute the report
	for _, t := range sites {
		if t.isBlacklisted {
			report.Blacklisted++
		}
		// Found a "clean clean" site
		if !t.isBlacklisted && !t.isMalwareFound {
			report.NoIssuesFound++
		}
	}
	return report, nil
}

func state(s string) (bool, error) {
	switch s {
	case clean:
		return false, nil
	case blacklisted, malwareFound:
		return true, nil
	}
	return false, errMalformedLine
}
