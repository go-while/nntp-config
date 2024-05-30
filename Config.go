package config

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

var (
	RamCache RAM
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
	Hostname string `json:"Hostname"`
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
	StorageXrefLinker bool   `json:"StorageXrefLinker"`
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

func CFG_reload(timer <-chan time.Time) (newC *CFG, newT <-chan time.Time, retbool bool) {
	// check if cfg needs reload
	// eats and checks the timer
	// returns retbool false or newconfig+newtimer
	select {
	case <-timer:
		newC = RamCache.ReadRAM_CFG()
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

func (ram *RAM) Refresh_RAM_CFG(DEBUG bool, cfg *CFG, err error) (*CFG, error) {
	if err != nil {
		log.Printf("ERROR Refresh_RAM_CFG caller err='%v'", err)
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("Error Refresh_RAM_CFG cfg=nil")
	}
	numpeers := len(cfg.Peers)
	//logf(DEBUG, "Refresh_RAM_CFG numpeers=%d", numpeers)

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
	cfg.Peers = nil // we dont need this slice anymore
	ram.mux.Unlock()

	//logf(DEBUG, "Refresh_RAM_CFG END cfg.PeersMAP=%d", len(cfg.PeersMAP))
	return cfg, nil
} // end func ram.Refresh_RAM_CFG
