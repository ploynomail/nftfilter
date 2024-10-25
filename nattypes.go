package nftfilter

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

var Accept = nftables.ChainPolicyAccept

const NatTable = "nftfilter"
const SNatChain = "nftfilter_snat"
const DNatChain = "nftfilter_dnat"

type NatType int8

const (
	SNat NatType = iota // 0
	DNat                // 1
)

type Nat struct {
	ID              uint64  `json:"id"`
	NatType         NatType `json:"nat_type"`
	Dest            string  `json:"dest"`             // 10.0.0.2/24 or 10.0.0.2-10.0.0.4 or 10.0.0.2,10.0.0.3,10.0.0.4
	Source          string  `json:"source"`           // 10.0.0.2/24 or 10.0.0.2-10.0.0.4 or 10.0.0.2,10.0.0.3,10.0.0.4
	DestPort        string  `json:"dest_port"`        // 80 or 80-90 or 80,90
	SourcePort      string  `json:"source_port"`      // 80 or 80-90 or 80,90
	OutputIP        string  `json:"output_ip"`        // 10.0.0.2/24 or 10.0.0.2-10.0.0.4 or 10.0.0.2,10.0.0.3,10.0.0.4
	OutputInterface string  `json:"output_interface"` // eth0
}

type Nats []Nat

func (n *Nats) Trigger(conn *nftables.Conn) error {
	if err := n.ReApply(conn); err != nil {
		return err
	}
	return nil
}

func (n *Nats) ReApply(conn *nftables.Conn) error {
	// 根据ID排序，id为优先级，id越小，优先级越高
	n.sortNats()
	if err := n.Flush(conn); err != nil {
		return err
	}
	rules, err := n.PrepareRules(conn)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		conn.AddRule(rule)
	}
	return nil
}

func (n *Nats) Flush(conn *nftables.Conn) error {
	if t, err := FilterTable(conn, NatTable); err != nil {
		return err
	} else if t != nil {
		conn.DelTable(t)
	}
	conn.AddTable(n.GetTable())
	conn.AddChain(n.GetDNatChain())
	conn.AddChain(n.GetSNatChain())
	conn.Flush()
	return nil
}

func (n *Nats) GetTable() *nftables.Table {
	return &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   NatTable,
	}
}

func (n *Nats) GetSNatChain() *nftables.Chain {
	return &nftables.Chain{
		Name:     SNatChain,
		Table:    n.GetTable(),
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &Accept,
	}
}

func (n *Nats) GetDNatChain() *nftables.Chain {
	return &nftables.Chain{
		Name:     DNatChain,
		Table:    n.GetTable(),
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	}
}

func (n *Nats) PrepareRules(conn *nftables.Conn) ([]*nftables.Rule, error) {
	var rules []*nftables.Rule = make([]*nftables.Rule, 0)
	for _, nat := range *n {
		var rule *nftables.Rule = &nftables.Rule{
			Table: n.GetTable(),
			Exprs: []expr.Any{},
		}

		if nat.Dest != "" {
			list, err := MatchDestIP(nat.Dest, conn)
			if err != nil {
				return nil, err
			}
			rule.Exprs = append(rule.Exprs, list...)
		}
		if nat.Source != "" {
			list, err := MatchSourceIP(nat.Source, conn)
			if err != nil {
				return nil, err
			}
			rule.Exprs = append(rule.Exprs, list...)
		}
		if nat.DestPort != "" {
			list, err := MatchDestPort(nat.DestPort, conn)
			if err != nil {
				return nil, err
			}
			rule.Exprs = append(rule.Exprs, list...)
		}
		if nat.SourcePort != "" {
			list, err := MatchSourcePort(nat.SourcePort, conn)
			if err != nil {
				return nil, err
			}
			rule.Exprs = append(rule.Exprs, list...)
		}

		switch nat.NatType {
		case SNat:
			rule.Chain = n.GetSNatChain()
			if nat.OutputIP != "" {
				rule.Exprs = append(rule.Exprs, VerdirtSNatCIDR(nat.OutputIP)...)
			}
			if nat.OutputInterface != "" {
				rule.Exprs = append(rule.Exprs, VerdirtSNatInterface(nat.OutputInterface)...)
			}
		case DNat:
			rule.Chain = n.GetDNatChain()
			if nat.OutputIP != "" {
				rule.Exprs = append(rule.Exprs, VerdirtDNatCIDR(nat.OutputIP)...)
			}
			if nat.OutputInterface != "" {
				rule.Exprs = append(rule.Exprs, VerdirtDNatInterface(nat.OutputInterface)...)
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
