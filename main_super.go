/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/gencfg"
	"github.com/KusakabeSi/EtherGuard-VPN/ipc"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

// ---------------------------------------------------------------------------
// Task 0.5 (supernode-http-only) — temporary stub.
//
// This file used to host the entire SuperNode WireGuard/UDP lifecycle:
// dual stack devices, dummy TAPs, private key / listen port / fwmark UAPI
// commands, the SUPER_Events register/pong channels, PushNhTable/PushPeerinfo/
// PushServerParams UDP fan-out, and RoutineTimeoutCheck's synthetic timer
// events. All of that code referenced mtypes.SuperConfig.PrivKeyV4,
// PrivKeyV6, ListenPort, FwMark, and API_Prefix — fields that task 1 removed
// when it switched the Super to HTTP-only control.
//
// Downstream tasks 5/6/7/8/9 all require `go test .` against the root
// package, so this file has to compile without the UDP lifecycle. Task 11
// (wave 5) will wire the real Control API v2 HTTP service into the shell
// left here. The shell preserves everything main_httpserver.go still needs:
//   - `checkNhTable` (graph/routing helper, kept for task 11)
//   - `printExampleSuperConf` (now prints the v2 Super example — task 2
//     changed GetExampleSuperConf's return type to mtypes.SuperConfigV2)
//   - `super_peeradd` / `super_peerdel` (state-init only — the WireGuard
//     peer-creation branches are gone; tasks 5/7 fill them in from v2
//     snapshots / events)
//   - `startUAPI` (still used by main_edge.go — must stay)
//   - `PushNhTable/PushPeerinfo/PushServerParams` are now no-op stubs so the
//     single remaining call site (main_httpserver.go edge_post_nodeinfo) and
//     any future call site keep compiling. They log once and return.
//
// Nothing here implements routes, auth, SSE, or state — those are task 11.
// ---------------------------------------------------------------------------

func checkNhTable(NhTable mtypes.NextHopTable, peers []mtypes.SuperPeerInfo) error {
	allpeer := make(map[mtypes.Vertex]bool, len(peers))
	for _, peer1 := range peers {
		allpeer[peer1.NodeID] = true
	}
	for _, peer1 := range peers {
		for _, peer2 := range peers {
			if peer1.NodeID == peer2.NodeID {
				continue
			}
			id1 := peer1.NodeID
			id2 := peer2.NodeID
			if dst, has := NhTable[id1]; has {
				if next, has2 := dst[id2]; has2 {
					if _, hasa := allpeer[next]; hasa {

					} else {
						return fmt.Errorf("NextHopTable[%v][%v]=%v which is not in the peer list", id1, id2, next)
					}
				} else {
					return fmt.Errorf("NextHopTable[%v][%v] not found", id1, id2)
				}
			} else {
				return fmt.Errorf("NextHopTable[%v] not found", id1)
			}
		}
	}
	return nil
}

func printExampleSuperConf() {
	// gencfg.GetExampleSuperConf now returns mtypes.SuperConfigV2 (task 2).
	// The legacy SuperConfig Super/UDP fields are no longer accepted by the
	// YAML parser (ControlV2ErrLegacyUDPField), so an "example" dump of the
	// old shape would mislead users.
	sconfig, _ := gencfg.GetExampleSuperConf("", true)
	scprint, _ := yaml.Marshal(sconfig)
	fmt.Print(string(scprint))
}

// Super is the HTTP-only Super control-service entry point. Until task 11
// wires in the real v2 HTTP control plane, it loads + validates the legacy
// SuperConfig (preserved for backward parsing compatibility during the
// migration window) and idles until SIGTERM/SIGINT so that `-mode super` is
// a valid CLI entry without crash-looping. The config's HTTP listen ports
// (ListenPort_EdgeAPI / ListenPort_ManageAPI) and API_Prefix are still
// parsed but not bound — task 11 will bind them.
func Super(configPath string, useUAPI bool, printExample bool, bindmode string) (err error) {
	if printExample {
		printExampleSuperConf()
		return nil
	}
	var sconfig mtypes.SuperConfig

	err = mtypes.ReadYaml(configPath, &sconfig)
	if err != nil {
		fmt.Printf("Error read config: %v\t%v\n", configPath, err)
		return err
	}

	// Reject configs that still carry UDP-only fields (PrivKeyV4/V6,
	// ListenPort, FwMark, API_Prefix). mtypes.ReadYaml uses a permissive
	// yaml.Unmarshal that silently drops unknown fields, so without this
	// pre-scan a v1 UDP Super YAML would be parsed as a config with empty
	// UDP fields and silently idle. mtypes.ControlV2ErrLegacyUDPField is
	// the typed error the v2 parser uses; we surface the same code so
	// downstream tooling gets a stable signal.
	if present, name := legacyUDPFieldPresent(configPath); present {
		return fmt.Errorf("%w: config field %q is no longer accepted in -mode super (HTTP-only); use a v2 SuperConfigV2 YAML", &mtypes.ControlV2Error{Code: mtypes.ControlV2ErrLegacyUDPField}, name)
	}

	if sconfig.PeerAliveTimeout <= 0 {
		return fmt.Errorf("PeerAliveTimeout must > 0 : %v", sconfig.PeerAliveTimeout)
	}
	if sconfig.HttpPostInterval < 0 {
		return fmt.Errorf("HttpPostInterval must >= 0 : %v", sconfig.HttpPostInterval)
	} else if sconfig.HttpPostInterval > sconfig.PeerAliveTimeout {
		return fmt.Errorf("HttpPostInterval must <= PeerAliveTimeout : %v", sconfig.HttpPostInterval)
	}
	if sconfig.SendPingInterval <= 0 {
		return fmt.Errorf("SendPingInterval must > 0 : %v", sconfig.SendPingInterval)
	}
	if sconfig.RePushConfigInterval <= 0 {
		return fmt.Errorf("RePushConfigInterval must > 0 : %v", sconfig.RePushConfigInterval)
	}

	fmt.Fprintf(os.Stderr,
		"super: HTTP-only Super control service not yet wired (task 11); "+
			"node=%s idling until SIGTERM/SIGINT. ListenPort_EdgeAPI=%q ListenPort_ManageAPI=%q\n",
		sconfig.NodeName, sconfig.ListenPort_EdgeAPI, sconfig.ListenPort_ManageAPI)

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)
	<-term
	fmt.Fprintln(os.Stderr, "super: stub shutting down (task 11 will replace this shell)")
	return nil
}

// super_peeradd used to (a) decode the peer's pubkey, (b) create a
// WireGuard peer on http_device4 and http_device6 via SetEndpointFromConnURL,
// and (c) populate httpobj.http_PeerState with the legacy SuperParam hash
// (md5 of mtypes.API_SuperParams + http_HashSalt). The HTTP/UDP bind /
// peer-creation branches have been removed because they referenced
// sconfig.PrivKeyV4/V6/ListenPort/FwMark (gone) and *device.Device peer's
// UDP-side bind. main_httpserver.go still calls super_peeradd (manage_peeradd
// at HTTP /manage/peer/add) and super_peerdel (manage_peerdel at
// /manage/peer/del), and main_httpserver.go also reads httpobj.http_PeerState
// on every /edge/* request. To keep that boundary compiling without
// restructuring main_httpserver.go (tasks 8/9 own it), we preserve the
// httpobj state shape here and leave a TODO marker for task 5/7 to fill in
// the v2 snapshot/event-driven peer book-keeping.
func super_peeradd(peerconf mtypes.SuperPeerInfo) error {
	// No lock, lock before call me
	httpobj.http_PeerID2Info[peerconf.NodeID] = peerconf

	SuperParams := mtypes.API_SuperParams{
		SendPingInterval: httpobj.http_sconfig.SendPingInterval,
		HttpPostInterval: httpobj.http_sconfig.HttpPostInterval,
		PeerAliveTimeout: httpobj.http_sconfig.PeerAliveTimeout,
		AdditionalCost:   peerconf.AdditionalCost,
	}

	SuperParamStr, _ := json.Marshal(SuperParams)
	md5_hash_raw := md5.Sum(append(SuperParamStr, httpobj.http_HashSalt...))
	new_hash_str := hex.EncodeToString(md5_hash_raw[:])

	PS := PeerState{}
	PS.NhTableState.Store("")              // string
	PS.PeerInfoState.Store("")             // string
	PS.SuperParamState.Store(new_hash_str) // string
	PS.SuperParamStateClient.Store("")     // string
	PS.JETSecret.Store(mtypes.JWTSecret{}) // mtypes.JWTSecret
	PS.httpPostCount.Store(uint64(0))      // uint64
	PS.LastSeen.Store(time.Time{})         // time.Time
	httpobj.http_PeerState[peerconf.PubKey] = &PS

	httpobj.http_PeerIPs[peerconf.PubKey] = &HttpPeerLocalIP{}
	return nil
}

func super_peerdel(toDelete mtypes.Vertex) {
	// No lock, lock before call me
	if _, has := httpobj.http_PeerID2Info[toDelete]; !has {
		return
	}
	PubKey := httpobj.http_PeerID2Info[toDelete].PubKey
	delete(httpobj.http_PeerState, PubKey)
	delete(httpobj.http_PeerIPs, PubKey)
	delete(httpobj.http_PeerID2Info, toDelete)
	// TODO(supernode-http-only/task-11): push ServerUpdateMsg / Shutdown over
	// the v2 HTTP control plane (the legacy UDP super_peerdel_notify that
	// called httpobj.http_device4.SendPacket(...) is gone with the UDP
	// lifecycle).
}

// PushNhTable / PushPeerinfo / PushServerParams used to marshal an mtypes
// ServerUpdateMsg and fan it out per-peer via httpobj.http_device{4,6}
// .SendPacket over the legacy WireGuard UDP tunnel. Without the UDP
// lifecycle they have no transport, so they log once and return. main_httpserver.go
// calls PushNhTable(false) from edge_post_nodeinfo when the latency graph
// changes; the v2 control service (task 11) will replace this with an SSE
// event (peer_change / revision) so Edges pull the new snapshot on demand.

func PushNhTable(force bool) {
	fmt.Fprintln(os.Stderr, "super: PushNhTable stub (task 11 wires the v2 SSE event)")
}

func PushPeerinfo(force bool) {
	fmt.Fprintln(os.Stderr, "super: PushPeerinfo stub (task 11 wires the v2 SSE event)")
}

func PushServerParams(force bool) {
	fmt.Fprintln(os.Stderr, "super: PushServerParams stub (task 11 wires the v2 SSE event)")
}

// startUAPI is the UAPI socket listener used by main_edge.go. It must
// stay compiled; the Super runtime path no longer calls it (no Super
// device means no UAPI), but the symbol is shared.
func startUAPI(interfaceName string, logger *device.Logger, the_device *device.Device, errs chan error) (net.Listener, error) {
	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_EG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}
		// use supplied fd
		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		fmt.Printf("Error create UAPI socket \n")
		return nil, err
	}
	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		return nil, err
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go the_device.IpcHandle(conn)
		}
	}()
	logger.Verbosef("UAPI listener started")
	return uapi, err
}

// legacyUDPFieldPresent pre-scans a Super YAML file for any of the
// UDP-only field names that mtypes.SuperConfig no longer carries. It
// catches the common mistake of feeding a v1 UDP Super YAML into
// `-mode super` (now HTTP-only) without waiting for mtypes.ReadYaml's
// silent drop to mis-route the operator. Returns (true, fieldName) on
// the first hit; (false, "") if the file is clean.
func legacyUDPFieldPresent(configPath string) (bool, string) {
	raw, err := ioutil.ReadFile(configPath)
	if err != nil {
		return false, ""
	}
	for _, name := range []string{"PrivKeyV4", "PrivKeyV6", "ListenPort", "FwMark", "API_Prefix"} {
		// Match top-level key (`^name:`) only — same-shape keys nested
		// under a v2 SuperNodeV2 etc. are legitimate.
		if bytes.HasPrefix(raw, []byte(name+":")) ||
			bytes.Contains(raw, []byte("\n"+name+":")) {
			return true, name
		}
	}
	_ = strings.HasPrefix // keep "strings" import in case future checks need it
	return false, ""
}
