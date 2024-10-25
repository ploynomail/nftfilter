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

func GetAnAnonymousSet() *nftables.Set {
	return &nftables.Set{
		Anonymous: true,
		Constant:  true,
	}
}

// Handle the port and its port return and return a set
func HandlePortAndRange(portStr string) (set []nftables.SetElement, err error) {
	if portStr == "" {
		return nil, errors.New("port is empty")
	}
	// if contains - or , then it is a range or a set
	if strings.Contains(portStr, "-") && len(strings.Split(portStr, "-")) == 2 {
		// range
		startPort := strings.Split(portStr, "-")[0]
		endPort := strings.Split(portStr, "-")[1]
		startPortInt, err := strconv.Atoi(startPort)
		if err != nil {
			return nil, err
		}
		endPortInt, err := strconv.Atoi(endPort)
		if err != nil {
			return nil, err
		}
		return []nftables.SetElement{
			{
				Key: []byte(IntToBytes(startPortInt)),
			},
			{
				Key:         []byte(IntToBytes(endPortInt)),
				IntervalEnd: true,
			},
		}, nil
	} else if strings.Contains(portStr, ",") {
		// set
		var setElements []nftables.SetElement
		for _, port := range strings.Split(portStr, ",") {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}
			setElements = append(setElements, nftables.SetElement{
				Key: []byte(IntToBytes(portInt)),
			})
		}
		return setElements, nil
	} else {
		// single
		portInt, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		if portInt < 0 || portInt > 65535 {
			return nil, errors.New("port is out of range")
		}
		return []nftables.SetElement{
			{
				Key: IntToBytes(portInt),
			},
		}, nil
	}
}

func HandleIPAndRange(ipStr string) (set []nftables.SetElement, err error) {
	if ipStr == "" {
		return nil, errors.New("ip is empty")
	}
	// if contains - or , then it is a range or a set
	if strings.Contains(ipStr, "-") && len(strings.Split(ipStr, "-")) == 2 {
		if net.ParseIP(strings.Split(ipStr, "-")[0]) == nil || net.ParseIP(strings.Split(ipStr, "-")[1]) == nil {
			return nil, errors.New("ip is invalid")
		}
		// range
		return []nftables.SetElement{
			{
				Key: []byte(strings.Split(ipStr, "-")[0]),
			},
			{
				Key:         []byte(strings.Split(ipStr, "-")[1]),
				IntervalEnd: true,
			},
		}, nil
	} else if strings.Contains(ipStr, ",") {
		// set
		var setElements []nftables.SetElement
		for _, ip := range strings.Split(ipStr, ",") {
			if net.ParseIP(ip) == nil {
				return nil, errors.New("ip is invalid")
			}
			setElements = append(setElements, nftables.SetElement{
				Key: []byte(ip),
			})
		}
		return setElements, nil
	} else {
		// single
		if net.ParseIP(ipStr) == nil {
			return nil, errors.New("ip is invalid")
		}
		return []nftables.SetElement{
			{
				Key: []byte(ipStr),
			},
		}, nil
	}
}

func IntToBytes(n int) []byte {
	x := int16(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}
