package nftfilter

import (
	"github.com/google/nftables"
)

type NftFilter struct {
	Conn *nftables.Conn
	Nats Nats
	// you can add more rules here
}

func NewNftFilter() (*NftFilter, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	return &NftFilter{Conn: conn}, nil
}

func (n *NftFilter) ChangeNats(nats Nats) {
	n.Nats = nats
}

func (n *NftFilter) Trigger() error {
	if err := n.Nats.ReApply(n.Conn); err != nil {
		return err
	}
	// you can add more filters here
	return nil
}

func (n *NftFilter) Clean() error {
	if err := n.Nats.Flush(n.Conn); err != nil {
		return err
	}
	// you can add more filters here

	return nil
}

func (n *NftFilter) Flush() error {
	if err := n.Conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (n *NftFilter) Close() error {
	return n.Conn.CloseLasting()
}
