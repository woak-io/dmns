package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var globalWordMap, globalWordList = createWordMap()

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			ip := "qwe"
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func createWordMap() (map[string]int, []string) {
	b, err := os.ReadFile("dip_wordlist.txt")
	if err != nil {
		panic(err)
	}
	wordList := strings.Split(string(b), "\n")

	if len(wordList) != 2048 {
		panic(fmt.Sprintf("word list is not the correct size: %d", len(wordList)))
	}

	wmap := make(map[string]int)
	for i, curWord := range wordList {
		if len(curWord) == 0 {
			panic(fmt.Sprintf("Couldn't create word list: word %d is blank", i))
		}
		wmap[curWord] = i
	}

	return wmap, wordList
}

func mnemonicToIPv4(mnemonic string) (ip net.IP) {
	re, err := regexp.Compile(`[.^_-]+`)
	if err != nil {
		panic("issue compiling regexp")
	}
	words := re.Split(mnemonic, -1)
	wordNums := make([]uint64, 0, 3)

	for _, w := range words {
		lw := strings.ToLower(w)
		if len(wordNums) == 3 {
			break
		}
		if num, ok := globalWordMap[lw]; ok {
			wordNums = append(wordNums, uint64(num))
		}
	}

	if len(wordNums) != 3 {
		return nil
	}

	// 2048**3/2 == (2**32) | 2048**3 == (2**33)
	ip = make(net.IP, 4)
	ipInt := (wordNums[0]<<22 | wordNums[1]<<11 | wordNums[2]) % (1 << 32)
	binary.BigEndian.PutUint32(ip, uint32(ipInt))
	return ip
}

func ipv4ToMnemonic(ip string, top bool) (string, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "", errors.New("unable to parse ip: " + ip)
	}

	ipAddr = ipAddr.To4()
	if ipAddr == nil {
		return "", errors.New("ipv6 address are not supported")
	}

	var long uint32
	binary.Read(
		bytes.NewBuffer(ipAddr.To4()),
		binary.BigEndian, &long,
	)

	ipInt := int64(long)

	if top {
		ipInt += (1 << 32)
	}

	i1 := uint32(ipInt >> 22 & 0x7FF)
	i2 := uint32(ipInt >> 11 & 0x7FF)
	i3 := uint32(ipInt & 0x7FF)

	mnemonicList := []string{
		globalWordList[i1],
		globalWordList[i2],
		globalWordList[i3],
	}

	return strings.Join(mnemonicList, "-"), nil
}

func main() {
	ip := mnemonicToIPv4("wish.lol.witness.wolf.ge")
	fmt.Println(ip.String())

	fmt.Println(ipv4ToMnemonic("127.0.0.1", false))
	fmt.Println(ipv4ToMnemonic("127.0.0.2", false))
	fmt.Println(ipv4ToMnemonic("127.0.0.3", false))
	fmt.Println(ipv4ToMnemonic("127.0.0.4", false))
	fmt.Println(ipv4ToMnemonic("127.0.0.5", false))
	fmt.Println(ipv4ToMnemonic("127.0.0.6", false))

	fmt.Println(ipv4ToMnemonic("192.168.0.1", false))
	fmt.Println(ipv4ToMnemonic("192.168.0.1", true))

	ip = mnemonicToIPv4("abandon-abandon-abandon")
	fmt.Println(ip.String())

	ip = mnemonicToIPv4("zoo-zoo-zoo")
	fmt.Println(ip.String())

	os.Exit(0)

	// attach request handler func
	dns.HandleFunc("service.", handleDnsRequest)

	// start server
	port := 5353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)

	defer server.Shutdown()
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
