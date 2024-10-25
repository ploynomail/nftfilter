package nftfilter

import (
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
	return nil
}

func VerdirtDNatCIDR(dNatCIDR string) []expr.Any {
	return nil
}

func VerdirtDNatInterface(dNatInterface string) []expr.Any {
	return nil
}
