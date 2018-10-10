package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

var (
	ResultPath = "README.md"

	WhoisServerAddr = "whois.iana.org:43"

	TldUrl = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

	NoServerFound = errors.New("no whois server found")

	semNum = 100
)

type item struct {
	tld    string
	server string
}

func main() {
	lg := zap.NewExample()
	var wg sync.WaitGroup
	sem := make(chan struct{}, semNum)
	defer close(sem)

	f, err := initReadme(ResultPath)
	if err != nil {
		lg.Fatal("create README.md failed")
	}

	// header
	fmt.Fprintf(f, "|%s|%s|\n", "TLD", "WHOIS SERVER")
	fmt.Fprintf(f, "|---|---|\n")

	tlds, err := getAllTlds()
	if err != nil {
		lg.Fatal("get tlds from iana failed", zap.Error(err))
	}

	tabc := make(chan item)
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case it := <-tabc:
				fmt.Fprintf(f, "|%s|%s|\n", it.tld, it.server)
			case <-time.After(time.Second * 5):
				return
			}
		}
	}()

	for _, tld := range tlds {
		sem <- struct{}{}
		wg.Add(1)
		go func(tld string) {
			defer func() {
				wg.Done()
				<-sem
			}()

			server, err := queryWhoisServer(tld)
			if err != nil {
				lg.Info("get whois server  failed", zap.String("tld", tld), zap.Error(err))
			}
			tabc <- item{tld, server}
		}(tld)
	}

	wg.Wait()
	lg.Info("done")
}

func initReadme(path string) (io.Writer, error) {
	os.RemoveAll(path)
	return os.Create(path)
}

func getAllTlds() (tlds []string, err error) {
	res, err := http.Get(TldUrl)
	if err != nil {
		return nil, err
	}

	sc := bufio.NewScanner(res.Body)

	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 0 {
			tlds = append(tlds, line)
		}
	}

	if err = sc.Err(); err != nil {
		return nil, err
	}

	return
}

func queryWhoisServer(tld string) (server string, err error) {
	conn, err := net.Dial("tcp", WhoisServerAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", tld)

	return search(conn)
}

func search(r io.Reader) (server string, err error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "whois:") {
			ts := strings.Fields(line)
			server = ts[len(ts)-1]
			return
		}
	}
	if err = sc.Err(); err != nil {
		return "", err
	}
	return "", NoServerFound
}
