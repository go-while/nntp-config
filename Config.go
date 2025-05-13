package config

import (
	"fmt"
	"log"
	"net"
	//"net/netip"
	"io/ioutil"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

var (
	//RamCache RAM
)

type CFG struct {
	Settings SETTINGS
	Peers    []PEER          // slice of peers
	PeersMAP map[string]PEER // key: peer.Hostname
} // end type CFG

type RAM struct {
	mux      sync.RWMutex
	Cfg      CFG
	PeersMAP map[string]PEER // key: peer.Hostname
} // end type RAM

type SETTINGS struct {
	Hostname string   `json:"Hostname"`
	//Max_Workers       int    `json:"Max_Workers"`
	Reload_CFG        int64  `json:"Reload_CFG"`
	DelayConn         int64  `json:"DelayConn"`
	Debug             bool   `json:"Debug"`
	Debug_Daemon      bool   `json:"Debug_Daemon"`
	Debug_CLI         bool   `json:"Debug_CLI"`
	Daemon_Host       string `json:"Daemon_Host"`
	Daemon_TCP        string `json:"Daemon_TCP"`
	PortsTCP          string `json:"PortsTCP"`
	PortsSSL          string `json:"PortsSSL"`
	Logs_File         string `json:"Logs_File"`
	SSL_CRT           string `json:"SSL_CRT"`
	SSL_KEY           string `json:"SSL_KEY"`
	Json_AuthFile     string `json:"Json_AuthFile"`
	MinPWLen          int    `json:"MinPWLen"`
	LIST_NeedsAuth    bool   `json:"LIST_NeedsAuth"`
	Overview          bool   `json:"Overview"`
	OverviewDir       string `json:"OverviewDir"`
	ActiveDir         string `json:"ActiveDir"`
	AcceptAllGroups   bool   `json:"AcceptAllGroups"`
	AcceptMaxGroups   int    `json:"AcceptMaxGroups"`
	StorageDir        string `json:"StorageDir"`
	CycBufsDir        string `json:"CycBufsDir"`
	StorageXrefLinker bool   `json:"StorageXrefLinker"`
	StorageAddXref    bool   `json:"StorageAddXref"`
	HashDBsqlUser     string `json:"HashDBsqlUser"`
	HashDBsqlPass     string `json:"HashDBsqlPass"`
	HashDBsqlHost     string `json:"HashDBsqlHost"`
	HashDBsqlDBName   string `json:"HashDBsqlDBName"`
} // end type SETTINGS

type PEER struct {
	Enabled        bool
	ReadOnlyAccess bool
	Hostname       string // fqdn / rdns (used as key in RAM PEERS MAP)
	Port           int    // default: 119
	Addr4          string // ipv4 address (for outgoing requests)
	Addr6          string // ipv6 address (for outgoing requests)
	Cidr4          string // ipv4 cidr range (allows incoming requests)
	Cidr6          string // ipv6 cidr range (allows incoming requests)
	Speedlimit     int64  // speedlimit per conn for sending to peer or if peer downloads actively: in KByte/s
	MaxconnsI      int    // limits incoming connections from peer
	MaxconnsO      int    // limits outgoing connections to peer
	//BW_I      int    // limits incoming bandwidth from peer
	//BW_O      int    // limits outgoing bandwidth to peer
	L_Auth_User    string // peer needs this user:pass to auth locally
	L_Auth_Pass    string // peer needs this user:pass to auth locally
	R_Auth_User    string // we have to use this creds when connecting
	R_Auth_Pass    string // we have to use this creds when connecting
	R_SSL          bool   // connect with ssl to peer
	R_SSL_Insecure bool   // allow connection to peer with self-signed or invalid/expired certs
} // end type PEER

/*
 *
 * import "github.com/go-while/nntp-config"
 *
 * type (
 * 	PEER     = config.PEER
 * 	SETTINGS = config.SETTINGS
 * 	CFG      = config.CFG
 * 	RAM      = config.RAM
 * )
 *	var (
 *		RamCache               RAM
 * )
 *
 *
 *	cfg, err := RamCache.Refresh_RAM_CFG(config.ReadConfig(true, conf_file))
 *	if cfg == nil || err != nil {
 *		os.Exit(1)
 *	}
 *
 */

func ReadConfig(DEBUG bool, filename string, oldcfg *CFG) (bool, *CFG, *CFG, error) {
	// first return bool is DEBUG! check error!
	//log.Printf("ReadConfig: file='%s'", filename)
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("ERROR ReadConfig err='%v'", err)
		return DEBUG, nil, nil, err
	}
	var cfg CFG
	err = json.Unmarshal(file, &cfg)
	if err != nil {
		log.Printf("ERROR ReadConfig Unmarshal err='%v'", err)
		return DEBUG, nil, nil, err
	}
	if !check_config_peers(cfg.PeersMAP) {
		return DEBUG, nil, nil, fmt.Errorf("ERROR !check_config_peers")
	}

	return DEBUG, &cfg, oldcfg, nil
} // end func ReadConfig

func check_config_peers(peers map[string]PEER) bool {
	for hostname, peer := range peers {
		if !StrIsIPv4(peer.Addr4) {
			log.Printf("ERROR check_config_peers: hostname=%s !StrIsIPv4(peer.Addr4)", hostname)
			return false
		}
		if !StrIsIPv6(peer.Addr6) {
			log.Printf("ERROR check_config_peers: hostname=%s !StrIsIPv6(peer.Addr6)", hostname)
			return false
		}
		if _, _, err := net.ParseCIDR(peer.Cidr4); err != nil {
			log.Printf("ERROR check_config_peers CIDR4 hostname=%s err='%v'", hostname, err)
			return false
		}
		if _, _, err := net.ParseCIDR(peer.Cidr6); err != nil {
			log.Printf("ERROR check_config_peers CIDR6 hostname=%s err='%v'", hostname, err)
			return false
		}
	}
	return true
} // end func check_config_peers

func CFG_reload(timer <-chan time.Time, ram *RAM) (newC *CFG, newT <-chan time.Time, retbool bool) {
	// check if cfg needs reload
	// eats and checks the timer
	// returns retbool false or newconfig+newtimer
	select {
	case <-timer:
		newC = ram.ReadRAM_CFG()
		newT = CFG_reload_timer(newC)
		retbool = true
		if strings.HasPrefix(newC.Settings.OverviewDir, "!") {
			newC.Settings.OverviewDir = ""
		}
		return newC, newT, true
	default: // pass
	}
	return nil, nil, false
} // end func cfg_reload

func CFG_reload_timer(cfg *CFG) <-chan time.Time {
	return time.After(time.Duration(cfg.Settings.Reload_CFG) * time.Second)
}

func (ram *RAM) ReadRAM_CFG() *CFG {
	ram.mux.RLock()
	cfg := ram.Cfg
	cfg.PeersMAP = ram.PeersMAP
	ram.mux.RUnlock()
	return &cfg
} // end func RamCache.ReadRAM_CFG

// get peer config from ram
func (ram *RAM) ReadRAM_PEER(hostname string) PEER {
	ram.mux.RLock()
	peer := ram.PeersMAP[hostname]
	ram.mux.RUnlock()
	return peer
} // end func ram.ReadRAM_PEER

func (ram *RAM) Refresh_RAM_CFG(DEBUG bool, cfg *CFG, oldcfg *CFG, err error) (*CFG, error) {
	if err != nil {
		log.Printf("ERROR Refresh_RAM_CFG caller err='%v'", err)
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("Error Refresh_RAM_CFG cfg=nil")
	}
	numpeers := len(cfg.Peers)
	oldlen := 0
	if oldcfg != nil {
		oldlen = len(oldcfg.PeersMAP)
		if oldlen != numpeers {
			log.Printf("Refresh_RAM_CFG numpeers=%d oldlen=%d", numpeers, oldlen)
		}
	}

	if cfg.Settings.AcceptMaxGroups == 0 {
		cfg.Settings.AcceptMaxGroups = 5
	}
	if cfg.Settings.Reload_CFG < 60 {
		cfg.Settings.Reload_CFG = 60
	}

	ram.mux.Lock()
	ram.Cfg.Settings = cfg.Settings
	ram.PeersMAP = make(map[string]PEER, numpeers)
	for _, peer := range cfg.Peers {
		ram.PeersMAP[peer.Hostname] = peer
	}
	cfg.PeersMAP = ram.PeersMAP
	//log.Printf("cfg.PeersMAP='%v'", cfg.PeersMAP)
	cfg.Peers = nil // we dont need this slice anymore
	ram.mux.Unlock()

	//log.Printf("Refresh_RAM_CFG END cfg.PeersMAP=%d", len(cfg.PeersMAP))
	return cfg, nil
} // end func ram.Refresh_RAM_CFG

func StrIsIPv4(address string) bool {
	testInput := net.ParseIP(address)
	if testInput.To4() != nil {
		log.Printf("!StrIsIPv4 addr='%s'", testInput, address)
		return false
	}
	return true
} // end func StrIsIPv4

func StrIsIPv6(address string) bool {
	// !!! must use before StrIsIPv6: net.SplitHostPort(address)
	// StrIsIPv6 works only with pure address without :port
	if strings.Contains(address, ":") {
		//log.Printf("StrIsIPv6 addr='%s'", address)
		return true
	}
	//log.Printf("!StrIsIPv6 addr='%s'", address)
	return false
} // end func StrIsIPv6

func MatchCIDR(remoteAddr string, matchCIDR string) (bool, error) {
	ip := net.ParseIP(remoteAddr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", remoteAddr)
	}

	_, ipNet, err := net.ParseCIDR(matchCIDR)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR block: %s", matchCIDR)
	}

	return ipNet.Contains(ip), nil
} // end func MatchCIDR: fully written by AI

func MatchRDNS(remoteAddr string, dnsquery_limiter chan struct{}) (string, bool) {
	// LookupAddr performs a reverse lookup for the given address,
	// returning a list of names mapping to that address.
	lock_dnsquery(dnsquery_limiter)
	hosts, err := net.LookupAddr(remoteAddr)
	if err != nil {
		log.Printf("ERROR MatchRDNS LookupHost err='%v'", err)
		return_dnsquery(dnsquery_limiter)
		return "", false
	}
	return_dnsquery(dnsquery_limiter)

	//log.Printf("Try MatchHost remoteAddr='%s' => hosts='%v'", remoteAddr, hosts)
	for _, hostname := range hosts {
		//log.Printf("Try MatchHost remoteAddr='%s' => hostname='%s'", remoteAddr, hostname)
		if MatchHost(hostname, remoteAddr, dnsquery_limiter) {
			//log.Printf("OK MatchRDNS -> MatchHost resolved remoteAddr='%s' ==> hostname='%s'", remoteAddr, hostname)
			return hostname, true
		}
	} // end for hosts

	log.Printf("FAIL MatchRDNS remoteAddr=%s", remoteAddr)
	return "", false
} // emd matchRDNS

func MatchHost(hostname string, match_remoteAddr string, dnsquery_limiter chan struct{}) bool {
	lock_dnsquery(dnsquery_limiter)
	defer return_dnsquery(dnsquery_limiter)

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		log.Printf("ERROR LOOKUP err='%v'")
		return false
	}
	//log.Printf("Try MatchHost hostname=%s => remoteAddr='%s' ? dns_reply addrs='%v'", hostname, match_remoteAddr, addrs)
	for _, addr := range addrs {
		if addr == match_remoteAddr {
			//log.Printf("OK MatchHost resolved remoteAddr='%s' => hostname='%s' addr='%s'", match_remoteAddr, hostname, addr)
			return true
		}
	} // end for LOOKUP
	//log.Printf("WARN MatchHost resolved remoteAddr='%s' => hostname='%s' addr='%s'", match_remoteAddr, hostname, addr)
	return false
} // end func MatchHost

func lock_dnsquery(dnsquery_limiter chan struct{}) {
	if dnsquery_limiter != nil {
		dnsquery_limiter <- struct{}{}
	}
}

func return_dnsquery(dnsquery_limiter chan struct{}) {
	if dnsquery_limiter != nil {
		<-dnsquery_limiter
	}
}

func ConnACL(DEBUG bool, cfg *CFG, conn net.Conn, force_connACL bool, dnsquery_limiter chan struct{}) (bool, *PEER) {

	//log.Printf("ConnACL peersMAP=%d", len(cfg.PeersMAP))

	/*
		func LookupAddr(addr string) (names []string, err error)
		func LookupCNAME(host string) (cname string, err error)
		func LookupHost(host string) (addrs []string, err error)
		func ParseCIDR(s string) (IP, *IPNet, error)
		func ParseIP(s string) IP
	*/
	ipv6 := false

	remoteAddr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Printf("ERROR ConnACL err='%v'", err)
		conn.Close()
		return false, nil
	}
	testv4 := net.ParseIP(remoteAddr)
	if testv4.To4() == nil {
		testv6 := net.ParseIP(remoteAddr)
		if testv6.To16() == nil {
			log.Printf("ERROR ConnACL net.ParseIP v4 or v6 failed")
			return false, nil
		}
		ipv6 = true
	}

	// loop over all peers
	// check if static ip matches
	//  else check hostname resolver
	/*
	ipv := 4
	if StrIsIPv6(remoteAddr) {
		ipv = 6
	}
	*/
	// every new request loops over peersmap to find matching peer.
	// TODO create maps for quick access for ip4|ip6 => peerid
	for _, peer := range cfg.PeersMAP {
		if !peer.Enabled {
			//log.Printf("IGNORE ConnACL !peer.Enabled hostname=%s", peer.Hostname)
			continue
		}
		if peer.Addr4 == "" && peer.Addr6 == "" && peer.Cidr4 == "" && peer.Cidr6 == "" {
			//log.Printf("IGNORE ConnACL hostname=%s peer.Addr+Cidr empty", peer.Hostname)
			continue
		}
		switch ipv6 {
		case false:
			if remoteAddr == peer.Addr4 {
				return true, &peer
			}
			if peer.Cidr4 != "" {
				if retbool, err := MatchCIDR(remoteAddr, peer.Cidr4); retbool && err == nil {
					return true, &peer
				}
			}

		case true:
			if remoteAddr == peer.Addr6 {
				return true, &peer
			}
			if peer.Cidr6 != "" {
				if retbool, err := MatchCIDR(remoteAddr, peer.Cidr6); retbool && err == nil {
					return true, &peer
				}
			}

		} // end switch switch(ipv)

		//log.Printf("ConnACL nomatch remoteAddr='%s' try next peer", remoteAddr)

		//log.Printf("connACL no match, try next: remoteAddr='%s' ipv%d vs. hostname=%s 6='%s' 4='%s'", remoteAddr, ipv, hostname, peer.Addr6, peer.Addr4) // spammy
	} // end for peers

	// static ip did not match any Peer.Hostname
	if hostname, retbool := MatchRDNS(remoteAddr, dnsquery_limiter); retbool == true {
		peer := cfg.PeersMAP[hostname]
		if peer.Hostname == hostname {
			log.Printf("ConnACL OK cfg.PeersMAP[hostname='%s']", hostname)
			return true, &peer
		} else {
			//log.Printf("ConnACL not found cfg.PeersMAP[hostname='%s']", hostname)
		}
	}
	if force_connACL {
		log.Printf("ConnACL denied remoteAddr='%s'", remoteAddr)
		conn.Close()
	}
	return false, nil
} // end func ConnACL

func RemoteAddr(conn net.Conn) string {
	remoteAddr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Printf("ERROR SRV.AddConn net.SplitHostPort err='%v'", err)
		conn.Close()
		return ""
	}
	return remoteAddr
} // end func RemoteAddr

/*
func ListenSSL(DEBUG bool, cfg *CFG, port string) {
	if cfg == nil || port == "" {
		return
	}
	ssl, err := tls.LoadX509KeyPair(cfg.Settings.SSL_CRT, cfg.Settings.SSL_KEY)
	if err != nil {
		log.Printf("ERROR tls.LoadX509KeyPair err='%v'", err)
		os.Exit(1)
	}
	ssl_conf := &tls.Config{
		Certificates: []tls.Certificate{ssl},
		//MinVersion: tls.VersionTLS12,
		//MaxVersion: tls.VersionTLS13,
	}
	listener_ssl, err := tls.Listen(cfg.Settings.Daemon_TCP, cfg.Settings.Daemon_Host+":"+port, ssl_conf)
	if err != nil {
		log.Printf("ERROR SSL err='%v'", err)
		return
	}
	defer listener_ssl.Close()
	log.Printf("Listen SSL: %s:%s", cfg.Settings.Daemon_Host, port)
	timer := CFG_reload_timer(cfg)
	force_connACL := true
listener:
	for {
		conn, err := listener_ssl.Accept()
		if err != nil {
			log.Printf("ERROR listener_ssl err='%v'", err)
			continue listener
		}
		// new incoming SSL connection
		ConnExtendReadDeadline(conn, 60)
		//if !Conn_Check(cfg, conn) {
		//	continue listener
		//}
		// check if cfg needs refresh from ram
		if newC, newT, retbool := CFG_reload(timer, &RamCache); retbool == true && newC != nil {
			cfg, timer = newC, newT
			DEBUG = cfg.Settings.Debug_Daemon
		}
		switch cfg.Settings.Json_AuthFile {
		case "":
			force_connACL = true
		default:
			force_connACL = false
		}

		if force_connACL {
			// check connACL
			if retbool, peer := ConnACL(DEBUG, cfg, conn, force_connACL, dnsquery_limiter); !retbool {
				// connacl denied
				continue listener
			} else {
				// incoming SSL conn passed ACL
				go SRV.HandleRequest(SRV.NewSession(conn, peer, cfg), cfg)
			}
		} else {
			_, peer := ConnACL(DEBUG, cfg, conn, force_connACL, dnsquery_limiter)
			go SRV.HandleRequest(SRV.NewSession(conn, peer, cfg), cfg)
		}

	} // end for listener_ssl
	//logf(DEBUG, "SSL listener_ssl closed %s", cfg.Settings.Daemon_Host)
} // end func ListenSSL

func ListenTCP(DEBUG bool, cfg *CFG, port string) {
	if cfg == nil || port == "" {
		return
	}
	var conn net.Conn
	var err error
	listener_tcp, err := net.Listen(cfg.Settings.Daemon_TCP, cfg.Settings.Daemon_Host+":"+port)
	if err != nil {
		log.Printf("ERROR TCP err='%v'", err)
		os.Exit(1)
	}
	defer listener_tcp.Close()
	log.Printf("Listen TCP: %s:%s", cfg.Settings.Daemon_Host, port)
	timer := CFG_reload_timer(cfg)
	force_connACL := true
listener:
	for {
		if conn, err = listener_tcp.Accept(); err != nil {
			log.Printf("ERROR listener_tcp err='%v'", err)
			continue listener
		}
		ConnExtendReadDeadline(conn, 60)
		// new incoming TCP connection
		//if !Conn_Check(cfg, conn) {
		//	continue listener
		//}
		// check if cfg needs refresh from ram
		if newC, newT, retbool := CFG_reload(timer, &RamCache); retbool == true && newC != nil {
			log.Printf("TCP: REFRESH CFG <- RAM")
			cfg, timer = newC, newT
			DEBUG = cfg.Settings.Debug_Daemon
		}
		switch cfg.Settings.Json_AuthFile {
		case "":
			force_connACL = true
		default:
			force_connACL = false
		}

		if force_connACL {
			// check connACL
			if retbool, peer := ConnACL(DEBUG, cfg, conn, force_connACL, dnsquery_limiter); !retbool {
				// connACL denied
				continue listener
			} else {
				// incoming TCP conn passed ACL
				go SRV.HandleRequest(SRV.NewSession(conn, peer, cfg), cfg)
			}
		} else {
			_, peer := ConnACL(DEBUG, cfg, conn, force_connACL, dnsquery_limiter)
			go SRV.HandleRequest(SRV.NewSession(conn, peer, cfg), cfg)
		}
	} // end for listener_tcp
	//logf(DEBUG, "TCP listener_tcp closed %s", cfg.Settings.Daemon_Host)
} // end func TCP
*/
