package nftfilter

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func MatchDestIP(destIP string, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	aSet := GetAnAnonymousSet(table, nftables.TypeIPAddr)
	aSet.KeyType = nftables.TypeIPAddr
	elements, err, interval := HandleIPAndRange(destIP)
	if err != nil {
		return nil, err
	}
	aSet.Interval = interval
	conn.AddSet(aSet, elements)
	return []expr.Any{
		// 匹配ip头部的目的ip字段
		&expr.Payload{
			OperationType:  expr.PayloadLoad,
			Base:           expr.PayloadBaseNetworkHeader,
			DestRegister:   1,
			SourceRegister: 0,
			Offset:         16,
			Len:            4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			DestRegister:   0,
			SetID:          aSet.ID,
		},
	}, nil
}

func MatchSourceIP(sourceIP string, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	aSet := GetAnAnonymousSet(table, nftables.TypeIPAddr)
	aSet.KeyType = nftables.TypeIPAddr
	elements, err, interval := HandleIPAndRange(sourceIP)
	if err != nil {
		return nil, err
	}
	aSet.Interval = interval
	conn.AddSet(aSet, elements)
	return []expr.Any{
		// 匹配ip头部的源ip字段
		&expr.Payload{
			OperationType:  expr.PayloadLoad,
			Base:           expr.PayloadBaseNetworkHeader,
			DestRegister:   1,
			SourceRegister: 0,
			Offset:         12,
			Len:            4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			DestRegister:   0,
			SetID:          aSet.ID,
		},
	}, nil
}

func MatchDestPort(destPort string, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	aSet := GetAnAnonymousSet(table, nftables.TypeInetService)
	aSet.KeyType = nftables.TypeInetService
	elements, err, interval := HandlePortAndRange(destPort)
	if err != nil {
		return nil, err
	}
	aSet.Interval = interval
	conn.AddSet(aSet, elements)

	return []expr.Any{
		// 匹配tcp协议
		&expr.Payload{
			OperationType:  expr.PayloadLoad,
			Base:           expr.PayloadBaseNetworkHeader,
			DestRegister:   1,
			SourceRegister: 0,
			Offset:         9,
			Len:            1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Data:     []byte{0x06},
			Register: 1,
		},
		// 匹配tcp头部的目的端口字段
		&expr.Payload{
			OperationType:  expr.PayloadLoad,
			Base:           expr.PayloadBaseTransportHeader,
			DestRegister:   1,
			SourceRegister: 0,
			Offset:         2,
			Len:            2,
		},
		&expr.Lookup{
			SourceRegister: 1,
			DestRegister:   0,
			SetID:          aSet.ID,
		},
	}, nil
}

func MatchSourcePort(sourcePort string, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	aSet := GetAnAnonymousSet(table, nftables.TypeInetService)
	aSet.KeyType = nftables.TypeInetService
	elements, err, interval := HandlePortAndRange(sourcePort)
	if err != nil {
		return nil, err
	}
	aSet.Interval = interval
	conn.AddSet(aSet, elements)
	return []expr.Any{
		// 匹配tcp头部的源端口字段
		&expr.Payload{
			OperationType:  expr.PayloadLoad,
			Base:           expr.PayloadBaseTransportHeader,
			DestRegister:   1,
			SourceRegister: 0,
			Offset:         0,
			Len:            2,
		},
		&expr.Lookup{
			SourceRegister: 1,
			DestRegister:   0,
			SetID:          aSet.ID,
		},
	}, nil
}
