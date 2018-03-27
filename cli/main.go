package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kpetku/quickreport"
)

func main() {
	clobber := flag.Bool("clobber", false, "overwrite lines that were previously read (e.g., if messages are being received concurrently).  For a strictly append only sequential log set this to false")
	flag.Parse()
	if len(os.Args) != 1 {
		r, err := quickreport.New(flag.Arg(0), *clobber)
		if err != nil {
			log.Fatalf("%s", err)
		}
		fmt.Printf("%d sites are currently blacklisted\n", r.Blacklisted)
		fmt.Printf("%d sites are currently clean\n", r.NoIssuesFound)
		fmt.Printf("%d sites previously had malware detected\n", r.MalwareDetected)
	} else {
		fmt.Printf("Invalid usage: ./cli list.txt or ./cli -help for help\n")
	}
}
