/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/google/shlex"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/gencfg"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
	yaml "gopkg.in/yaml.v2"
)

func printExampleEdgeConf() {
	tconfig, _ := gencfg.GetExampleEdgeConfV2("")
	toprint, _ := yaml.Marshal(tconfig)
	fmt.Print(string(toprint))
}

func Edge(configPath string, useUAPI bool, printExample bool, bindmode string) (err error) {
	if printExample {
		printExampleEdgeConf()
		return nil
	}
	var econfig mtypes.EdgeConfig
	var econfigV2 mtypes.EdgeConfigV2
	//printExampleConf()
	//return

	err = mtypes.ReadYaml(configPath, &econfigV2)
	if err != nil {
		return fmt.Errorf("parse v2 edge config %q: %w", configPath, err)
	}
	superNodeV2Enabled := econfigV2.SuperNodeV2.APIUrl != ""
	if superNodeV2Enabled {
		if err := econfigV2.Validate(); err != nil {
			return fmt.Errorf("validate v2 edge config %q: %w", configPath, err)
		}
		econfig.Interface = econfigV2.Interface
		econfig.NodeID = econfigV2.NodeID
		econfig.NodeName = econfigV2.NodeName
		econfig.DefaultTTL = econfigV2.DefaultTTL
		econfig.LogLevel = econfigV2.LogLevel
		econfig.Peers = econfigV2.Peers
		econfig.SuperNodeV2Enabled = true
	} else {
		err = mtypes.ReadYaml(configPath, &econfig)
	}
	if err != nil {
		fmt.Printf("Error read config: %v\t%v\n", configPath, err)
		return err
	}

	NodeName := econfig.NodeName
	if len(NodeName) > 32 {
		return errors.New("Node name can't longer than 32 :" + NodeName)
	}
	var logLevel int
	switch econfig.LogLevel.LogLevel {
	case "verbose", "debug":
		logLevel = device.LogLevelVerbose
	case "error":
		logLevel = device.LogLevelError
	case "silent":
		logLevel = device.LogLevelSilent
	default:
		logLevel = device.LogLevelError
	}
	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", NodeName),
	)

	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}

	var thetap tap.Device
	// open TUN device (or use supplied fd)
	switch econfig.Interface.IType {
	case "dummy":
		thetap, err = tap.CreateDummyTAP()
	case "stdio":
		thetap, err = tap.CreateStdIOTAP(econfig.Interface, econfig.NodeID)
	case "udpsock":
		thetap, err = tap.CreateUDPSockTAP(econfig.Interface, econfig.NodeID)
	case "tcpsock":
		thetap, err = tap.CreateSockTAP(econfig.Interface, "tcp", econfig.NodeID, econfig.LogLevel)
	case "unixsock":
		thetap, err = tap.CreateSockTAP(econfig.Interface, "unix", econfig.NodeID, econfig.LogLevel)
	case "unixgramsock":
		thetap, err = tap.CreateSockTAP(econfig.Interface, "unixgram", econfig.NodeID, econfig.LogLevel)
	case "unixpacketsock":
		thetap, err = tap.CreateSockTAP(econfig.Interface, "unixpacket", econfig.NodeID, econfig.LogLevel)
	case "fd":
		thetap, err = tap.CreateFdTAP(econfig.Interface, econfig.NodeID)
	case "vpp":
		thetap, err = tap.CreateVppTAP(econfig.Interface, econfig.NodeID, econfig.LogLevel.LogLevel)
	case "tap":
		thetap, err = tap.CreateTAP(econfig.Interface, econfig.NodeID)
	default:
		return errors.New("Unknown interface type:" + econfig.Interface.IType)
	}
	if err != nil {
		logger.Errorf("Failed to create TAP device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	if econfig.DefaultTTL <= 0 {
		return errors.New("DefaultTTL must > 0")
	}

	////////////////////////////////////////////////////
	// Config
	if !econfig.DynamicRoute.P2P.UseP2P && !econfig.SuperNodeV2Enabled {
		econfig.LogLevel.LogNTP = false // NTP in static mode is useless
	}
	graph, err := path.NewGraph(3, false, econfig.DynamicRoute.P2P.GraphRecalculateSetting, econfig.DynamicRoute.NTPConfig, econfig.LogLevel)
	if err != nil {
		return err
	}
	graph.SetNHTable(econfig.NextHopTable)

	EnabledAf := econfig.DisableAf.Disalbed2Enabled()

	the_device := device.NewDevice(thetap, econfig.NodeID, conn.NewDefaultBind(EnabledAf, bindmode, econfig.FwMark), logger, graph, false, configPath, &econfig, nil, nil, Version)
	defer the_device.Close()
	if superNodeV2Enabled {
		the_device.EnableSuperHTTP(econfigV2)
	}
	pk, err := device.Str2PriKey(econfig.PrivKey)
	if err != nil {
		fmt.Println("Error decode base64 ", err)
		return err
	}
	the_device.SetPrivateKey(pk)
	the_device.IpcSet("fwmark=" + fmt.Sprint(econfig.FwMark) + "\n")
	the_device.IpcSet("listen_port=" + strconv.Itoa(econfig.ListenPort) + "\n")
	the_device.SuperHTTPReady()
	the_device.IpcSet("replace_peers=true\n")
	for _, peerconf := range econfig.Peers {
		pk, err := device.Str2PubKey(peerconf.PubKey)
		if err != nil {
			fmt.Println("Error decode base64 ", err)
			return err
		}
		the_device.NewPeer(pk, peerconf.NodeID, false, peerconf.PersistentKeepalive)
		if peerconf.EndPoint != "" {
			peer := the_device.LookupPeer(pk)
			err = peer.SetEndpointFromConnURL(peerconf.EndPoint, EnabledAf, econfig.AfPrefer, peerconf.Static)
			if err != nil {
				if endpointErr := initialPeerEndpointError(econfig.DynamicRoute.P2P.UseP2P, err); endpointErr != nil {
					logger.Errorf("Failed to set endpoint %v: %v", peerconf.EndPoint, endpointErr)
					return endpointErr
				}
				peer.AddEndpointRetry(peerconf.EndPoint, peerconf.Static)
				logger.Errorf("Initial peer endpoint unavailable; P2P will retry: endpoint=%v error=%v", peerconf.EndPoint, err)
			}
		}
	}

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	if useUAPI {
		startUAPI(NodeName, logger, the_device, errs)
	}

	if econfig.PostScript != "" {
		envs := make(map[string]string)
		nid := econfig.NodeID
		nid_bytearr := []byte{0, 0}
		MacAddr, _ := tap.GetMacAddr(econfig.Interface.MacAddrPrefix, uint32(nid))
		binary.LittleEndian.PutUint16(nid_bytearr, uint16(nid))

		envs["EG_MODE"] = "edge"
		envs["EG_NODE_NAME"] = econfig.NodeName
		envs["EG_NODE_ID_INT_DEC"] = fmt.Sprintf("%d", nid)
		envs["EG_NODE_ID_BYTE0_DEC"] = fmt.Sprintf("%d", nid_bytearr[0])
		envs["EG_NODE_ID_BYTE1_DEC"] = fmt.Sprintf("%d", nid_bytearr[1])
		envs["EG_NODE_ID_INT_HEX"] = fmt.Sprintf("%x", nid)
		envs["EG_NODE_ID_BYTE0_HEX"] = fmt.Sprintf("%X", nid_bytearr[0])
		envs["EG_NODE_ID_BYTE1_HEX"] = fmt.Sprintf("%X", nid_bytearr[1])
		envs["EG_INTERFACE_NAME"] = econfig.Interface.Name
		envs["EG_INTERFACE_TYPE"] = econfig.Interface.IType
		envs["EG_INTERFACE_MAC_PREFIX"] = econfig.Interface.MacAddrPrefix
		envs["EG_INTERFACE_MAC_ADDR"] = MacAddr.String()

		cmdarg, err := shlex.Split(econfig.PostScript)
		if err != nil {
			return fmt.Errorf("error parse PostScript %v", err)
		}
		if econfig.LogLevel.LogInternal {
			fmt.Printf("PostScript: exec.Command(%v)\n", cmdarg)
		}
		cmd := exec.Command(cmdarg[0], cmdarg[1:]...)
		cmd.Env = os.Environ()
		for k, v := range envs {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("exec.Command(%v) failed with %v", cmdarg, err)
		}
		if econfig.LogLevel.LogInternal {
			fmt.Printf("PostScript output: %s\n", string(out))
		}
	}

	// wait for program to terminate
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	the_device.Chan_Device_Initialized <- struct{}{}
	mtypes.SdNotify(false, mtypes.SdNotifyReady)
	SdNotify, err := mtypes.SdNotify(false, mtypes.SdNotifyReady)
	if econfig.LogLevel.LogInternal {
		fmt.Printf("Internal: SdNotify:%v err:%v\n", SdNotify, err)
	}

	select {
	case <-term:
	case <-errs:
	case errcode := <-the_device.Wait():
		if errcode != 0 {
			return syscall.Errno(errcode)
		}
	}
	logger.Verbosef("Shutting down")
	return
}
