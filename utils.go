package nftfilter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
)

func FilterTable(conn *nftables.Conn, tableName string) (table *nftables.Table, err error) {
	tableList, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tableList {
		if t.Name == tableName {
			return t, nil
		}
	}
	return nil, nil
}

// Nats sort function Start
func (n *Nats) sortNats() {
	sort.Sort(n)
}
func (n *Nats) Len() int {
	return len(*n)
}

func (n *Nats) Less(i, j int) bool {
	return (*n)[i].ID < (*n)[j].ID
}

func (n *Nats) Swap(i, j int) {
	(*n)[i], (*n)[j] = (*n)[j], (*n)[i]
}

// Nats sort function End

func GetAnAnonymousSet(table *nftables.Table, KeyType nftables.SetDatatype) *nftables.Set {
	return &nftables.Set{
		Table:     table,
		Anonymous: true,
		Constant:  true,
		KeyType:   KeyType,
	}
}

// Handle the port and its port return and return a set
func HandlePortAndRange(portStr string) (set []nftables.SetElement, err error, interval bool) {
	if portStr == "" {
		return nil, errors.New("port is empty"), false
	}
	// if contains - or , then it is a range or a set
	if strings.Contains(portStr, "-") && len(strings.Split(portStr, "-")) == 2 {
		// range
		startPort := strings.Split(portStr, "-")[0]
		endPort := strings.Split(portStr, "-")[1]
		if startPort == "" || endPort == "" || startPort == endPort || startPort > endPort {
			return nil, errors.New("port range is invalid"), false
		}
		startPortInt, err := strconv.Atoi(startPort)
		if err != nil {
			return nil, err, false
		}
		endPortInt, err := strconv.Atoi(endPort)
		if err != nil {
			return nil, err, false
		}
		return []nftables.SetElement{
			{
				Key: []byte(IntToBytes(startPortInt)),
			},
			{
				Key:         []byte(IntToBytes(endPortInt)),
				IntervalEnd: true,
			},
		}, nil, true
	} else if strings.Contains(portStr, ",") {
		// set
		var setElements []nftables.SetElement
		for _, port := range strings.Split(portStr, ",") {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				return nil, err, false
			}
			setElements = append(setElements, nftables.SetElement{
				Key: []byte(IntToBytes(portInt)),
			})
		}
		return setElements, nil, false
	} else {
		// single
		portInt, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err, false
		}
		if portInt < 0 || portInt > 65535 {
			return nil, errors.New("port is out of range"), false
		}
		return []nftables.SetElement{
			{
				Key: IntToBytes(portInt),
			},
		}, nil, false
	}
}

func HandleIPAndRange(ipStr string) (set []nftables.SetElement, err error, interval bool) {
	if ipStr == "" {
		return nil, errors.New("ip is empty"), false
	}
	// if contains - or , then it is a range or a set
	if strings.Contains(ipStr, "-") && len(strings.Split(ipStr, "-")) == 2 {
		if net.ParseIP(strings.Split(ipStr, "-")[0]) == nil || net.ParseIP(strings.Split(ipStr, "-")[1]) == nil {
			return nil, errors.New("ip is invalid"), false
		}
		startIP := net.ParseIP(strings.Split(ipStr, "-")[0]).To4()
		endIP := net.ParseIP(strings.Split(ipStr, "-")[1]).To4()
		// range
		return []nftables.SetElement{
			{
				Key: startIP,
			},
			{
				Key:         endIP,
				IntervalEnd: true,
			},
		}, nil, true
	} else if strings.Contains(ipStr, ",") {
		// set
		var setElements []nftables.SetElement
		for _, ip := range strings.Split(ipStr, ",") {
			if net.ParseIP(ip) == nil {
				return nil, errors.New("ip is invalid"), false
			}
			setElements = append(setElements, nftables.SetElement{
				Key: net.ParseIP(ip).To4(),
			})
		}
		return setElements, nil, false
	} else if strings.Contains(ipStr, "/") {
		// cidr
		startIP, endIp, err := GetStartAndEndIp(ipStr)
		if err != nil {
			return nil, err, false
		}
		return []nftables.SetElement{
			{
				Key:         incrementIP(endIp).To4(),
				IntervalEnd: true,
			},
			{
				Key: startIP.To4(),
			},
			{
				Key:         []byte{0, 0, 0, 0},
				IntervalEnd: true,
			},
		}, nil, true
	} else {
		// single
		if net.ParseIP(ipStr) == nil {
			return nil, errors.New("ip is invalid"), false
		}
		return []nftables.SetElement{
			{
				Key: net.ParseIP(ipStr).To4(),
			},
		}, nil, false
	}
}

func IntToBytes(n int) []byte {
	x := int16(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

// ipToInt 将IPv4地址转换为一个整数
func ipToInt(ip net.IP) uint32 {
	var ipInt uint32
	for _, octet := range ip.To4() {
		ipInt = (ipInt << 8) + uint32(octet)
	}
	return ipInt
}

// intToIP 将整数转换回IPv4地址
func intToIP(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = byte((ipInt >> (24 - i*8)) & 0xFF)
	}
	return ip
}

// incrementIP 对IP地址进行+1操作
func incrementIP(ip net.IP) net.IP {
	ipInt := ipToInt(ip)
	ipInt++
	return intToIP(ipInt)
}

func GetStartAndEndIp(cidr string) (startIP, endIP net.IP, err error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	// 开始IP是IPNet结构的IP字段
	startIP = ipnet.IP

	// 结束IP是开始IP的广播地址
	endIP = make(net.IP, len(startIP))
	for i := range startIP {
		endIP[i] = startIP[i] | ^ipnet.Mask[i]
	}

	return startIP, endIP, nil
}
