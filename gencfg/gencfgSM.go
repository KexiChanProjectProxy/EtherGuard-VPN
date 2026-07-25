package gencfg

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
	yaml "gopkg.in/yaml.v2"
)

var gencfg_reader *bufio.Reader

func readFLn(promptF string, checkFn func(string) error, defaultAns func() string, args ...interface{}) string {
	defaultans := defaultAns()
	if defaultans != "" {
		fmt.Printf(promptF+" ("+defaultans+") :", args...)
	} else {
		fmt.Printf(promptF+" :", args...)
	}
	text, err := gencfg_reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	text = strings.Replace(text, "\n", "", -1)
	if text == "" {
		text = defaultans
	}
	if err := checkFn(text); err != nil {
		fmt.Println(err)
		return readFLn(promptF, checkFn, defaultAns, args...)
	}
	return text
}

func ParseIDs(s string) ([]int, int, int, error) {
	ret := make([]int, 0)
	if len(s) <= 3 || s[0] != '[' || s[len(s)-1] != ']' {
		return ret, 0, 0, fmt.Errorf("Parse Error: %v", s)
	}
	s = s[1 : len(s)-1]
	as := strings.Split(s, ",")
	min := math.MaxUint16
	max := 0
	for i, es := range as {
		if strings.Contains(es, "~") {
			esl := strings.SplitN(es, "~", 2)
			si, err := strconv.ParseInt(esl[0], 10, 16)
			if err != nil {
				return ret, min, max, err
			}
			ei, err := strconv.ParseInt(esl[1], 10, 16)
			if err != nil {
				return ret, min, max, err
			}
			if si >= ei {
				return ret, min, max, fmt.Errorf("end %v must > start %v", ei, si)
			}
			if int(si) < 0 {
				return ret, min, max, fmt.Errorf("node ID < 0 at element %v", i)
			}
			if min > int(si) {
				min = int(si)
			}
			if int(si) < max {
				return ret, min, max, fmt.Errorf("list out of order at the %vth element: %v", i, es)
			} else if int(si) == max {
				return ret, min, max, fmt.Errorf("duplicate id in the %vth element: %v", i, es)
			}
			max = int(ei)
			for ; si <= ei; si++ {
				ret = append(ret, int(si))
			}
		} else {
			si, err := strconv.ParseInt(es, 10, 16)
			if err != nil {
				return ret, min, max, err
			}
			if int(si) < max {
				return ret, min, max, fmt.Errorf("List out of order at the %vth element!", i)
			} else if int(si) == max {
				return ret, min, max, fmt.Errorf("duplicate id in the %vth element", i)
			}
			if min > int(si) {
				min = int(si)
			}
			max = int(si)
			ret = append(ret, int(si))
		}
	}
	return ret, min, max, nil
}

func printExampleSMCfg() {
	toprint, _ := yaml.Marshal(SMCfg{})
	fmt.Print(string(toprint))
}

func GenSuperCfg(configPath string, printExample bool) error {
	if printExample {
		printExampleSMCfg()
		return nil
	}
	var input SMCfg
	if err := mtypes.ReadYaml(configPath, &input); err != nil {
		return err
	}
	if err := validateSuperGeneratorInput(&input); err != nil {
		return err
	}
	if err := os.MkdirAll(input.ConfigOutputDir, 0o700); err != nil {
		return err
	}

	super, err := GetExampleSuperConf(resolveTemplate(configPath, input.SuperConfigTemplate), false)
	if input.SuperConfigTemplate != "" && err != nil {
		return fmt.Errorf("read Super v2 template: %w", err)
	}
	edgeTemplate, err := GetExampleEdgeConfV2(resolveTemplate(configPath, input.EdgeConfigTemplate))
	if err != nil {
		return fmt.Errorf("read Edge v2 template: %w", err)
	}
	applySuperInputs(&super, &input)

	nodeIDs, _, maxNodeID, err := ParseIDs(input.EdgeNode.NodeIDs)
	if err != nil {
		return err
	}
	macPrefix, err := edgeMacPrefix(input.EdgeNode.MacPrefix, maxNodeID)
	if err != nil {
		return err
	}
	if _, _, err := tap.GetIP(4, input.EdgeNode.IPv4Range, uint32(maxNodeID)); input.EdgeNode.IPv4Range != "" && err != nil {
		return err
	}
	if _, _, err := tap.GetIP(6, input.EdgeNode.IPv6Range, uint32(maxNodeID)); input.EdgeNode.IPv6Range != "" && err != nil {
		return err
	}
	if _, _, err := tap.GetIP(6, input.EdgeNode.IPv6LLRange, uint32(maxNodeID)); input.EdgeNode.IPv6LLRange != "" && err != nil {
		return err
	}

	writer := bulkFileWriter{files: make(map[string]fileWriterfile), ow: input.ConfigOutputDirOW}
	super.Peers = make([]mtypes.SuperConfigV2Peer, 0, len(nodeIDs))
	width := len(strconv.Itoa(maxNodeID))
	for _, rawID := range nodeIDs {
		nodeID := mtypes.Vertex(rawID)
		idstr := fmt.Sprintf("%0"+strconv.Itoa(width)+"d", rawID)
		controlKey := device.RandomPSK().ToString()
		edge := edgeTemplate
		edge.NodeID = nodeID
		edge.NodeName = input.NetworkName
		edge.Interface.Name = input.NetworkName
		if input.NetworkIFNameID {
			edge.NodeName += idstr
			edge.Interface.Name += idstr
		}
		edge.Interface.MacAddrPrefix = macPrefix
		edge.Interface.IPv4CIDR = input.EdgeNode.IPv4Range
		edge.Interface.IPv6CIDR = input.EdgeNode.IPv6Range
		edge.Interface.IPv6LLPrefix = input.EdgeNode.IPv6LLRange
		edge.SuperNodeV2 = mtypes.SuperNodeV2Ref{APIUrl: super.APIUrl, APIPrefix: super.APIPrefix, NodeID: input.Supernode.NodeID, ControlPSKey: controlKey}
		edge.Peers = clonePeersWithPairwisePSKs(edgeTemplate.Peers, super.UsePSKForInterEdge)
		if err := edge.Validate(); err != nil {
			return fmt.Errorf("validate Edge %d: %w", nodeID, err)
		}
		super.Peers = append(super.Peers, mtypes.SuperConfigV2Peer{NodeID: nodeID, NodeName: edge.NodeName, ControlPSKey: controlKey, AdditionalCost: 10})
		data, err := yaml.Marshal(edge)
		if err != nil {
			return err
		}
		writer.WriteFile(filepath.Join(input.ConfigOutputDir, input.NetworkName+"_edge"+idstr+".yaml"), data, 0o600)
	}
	if err := super.Validate(); err != nil {
		return fmt.Errorf("validate Super v2 config: %w", err)
	}
	data, err := yaml.Marshal(super)
	if err != nil {
		return err
	}
	writer.WriteFile(filepath.Join(input.ConfigOutputDir, input.NetworkName+"_super.yaml"), data, 0o600)
	return writer.Commit()
}

func validateSuperGeneratorInput(input *SMCfg) error {
	if len(input.NetworkName) > 10 {
		return fmt.Errorf("Name too long")
	}
	const allowed = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
	for _, c := range []byte(input.NetworkName) {
		if !strings.Contains(allowed, string(c)) {
			return fmt.Errorf("Name can only contain %v", allowed)
		}
	}
	if input.Supernode.APIURL == "" {
		return fmt.Errorf("Super Node API URL is required")
	}
	if input.Supernode.APIPrefix == "" {
		input.Supernode.APIPrefix = mtypes.ControlV2APIPrefix
	}
	if input.Supernode.NodeID == 0 {
		input.Supernode.NodeID = 1
	}
	return nil
}

func applySuperInputs(super *mtypes.SuperConfigV2, input *SMCfg) {
	super.NodeName = input.NetworkName + "SN"
	super.APIUrl = input.Supernode.APIURL
	super.APIPrefix = input.Supernode.APIPrefix
	if len(input.Supernode.STUNServers) > 0 {
		super.STUNServers = append([]string(nil), input.Supernode.STUNServers...)
	}
	setPositiveFloat(&super.STUNRequestTimeoutSeconds, input.Supernode.STUNRequestTimeoutSeconds)
	setPositiveFloat(&super.STUNRefreshIntervalSeconds, input.Supernode.STUNRefreshIntervalSeconds)
	setPositiveFloat(&super.PollIntervalSeconds, input.Supernode.PollIntervalSeconds)
	setPositiveFloat(&super.ReportIntervalSeconds, input.Supernode.ReportIntervalSeconds)
	setPositiveFloat(&super.HeartbeatIntervalSeconds, input.Supernode.HeartbeatIntervalSeconds)
	setPositiveFloat(&super.PeerAliveTimeoutSeconds, input.Supernode.PeerAliveTimeoutSeconds)
	if input.Supernode.EventReplay > 0 {
		super.EventReplay = input.Supernode.EventReplay
	}
	if input.Supernode.DampingFilterRadius > 0 {
		super.DampingFilterRadius = input.Supernode.DampingFilterRadius
	}
	if input.Supernode.UsePSKForInterEdge != nil {
		super.UsePSKForInterEdge = *input.Supernode.UsePSKForInterEdge
	}
	if input.Supernode.ManagementUser != "" {
		super.ManagementAuth.User = input.Supernode.ManagementUser
	}
	if input.Supernode.ManagementPasswordHash != "" {
		super.ManagementAuth.PasswordHash = input.Supernode.ManagementPasswordHash
	}
}

func setPositiveFloat(target *float64, candidate float64) {
	if candidate > 0 {
		*target = candidate
	}
}

func resolveTemplate(configPath, template string) string {
	if template == "" || filepath.IsAbs(template) {
		return template
	}
	return filepath.Join(filepath.Dir(configPath), template)
}

func edgeMacPrefix(requested string, maxNodeID int) (string, error) {
	if requested != "" {
		if _, err := tap.GetMacAddr(requested, uint32(maxNodeID)); err != nil {
			return "", err
		}
		return requested, nil
	}
	prefix := mtypes.RandomBytes(4, []byte{0xaa, 0xbb, 0xcc, 0xdd})
	prefix[0] &^= 1
	prefix[0] |= 2
	return fmt.Sprintf("%02X:%02X:%02X:%02X", prefix[0], prefix[1], prefix[2], prefix[3]), nil
}

func clonePeersWithPairwisePSKs(peers []mtypes.PeerInfo, enabled bool) []mtypes.PeerInfo {
	result := append([]mtypes.PeerInfo(nil), peers...)
	if enabled {
		for i := range result {
			result[i].PSKey = device.RandomPSK().ToString()
		}
	}
	return result
}
