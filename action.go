package nftfilter

import (
	"net"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func VerdirtAccept() expr.Any {
	return &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
}

func VerdirtDrop() expr.Any {
	return &expr.Verdict{
		Kind: expr.VerdictDrop,
	}
}

func VerdirtSNatCIDR(sNatCIDR string) []expr.Any {

	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     net.ParseIP(sNatCIDR).To4(),
		},
		&expr.NAT{
			Type:        expr.NATTypeSourceNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegAddrMax:  1,
			RegProtoMin: 0,
			RegProtoMax: 0,
			Random:      false, FullyRandom: false, Persistent: false, Prefix: false,
		},
	}
}

func VerdirtSNatInterface(sNatInterface string) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:            expr.MetaKeyOIFNAME,
			Register:       1,
			SourceRegister: false,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(sNatInterface),
		},
		&expr.Masq{
			Random: false, FullyRandom: false, Persistent: false,
			ToPorts: false, RegProtoMin: 0, RegProtoMax: 0,
		},
	}
}

func VerdirtDNatCIDR(dNatCIDR string) []expr.Any {

	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     net.ParseIP(dNatCIDR).To4(),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegAddrMax:  1,
			RegProtoMin: 0,
			RegProtoMax: 0,
			Random:      false, FullyRandom: false, Persistent: false, Prefix: false,
		},
	}
}
