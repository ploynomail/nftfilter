package nftfilter

import (
	"testing"
)

func TestNft(t *testing.T) {
	nftis, err := NewNftFilter()
	if err != nil {
		t.Error(err)
	}
	var nats Nats = []Nat{
		{
			ID:              1,
			NatType:         SNat,
			Dest:            "10.10.22.0/24",
			Source:          "192.168.2.2,192.168.2.23",
			DestPort:        "80-89",
			SourcePort:      "80",
			TargeIP:         "",
			OutputInterface: "enp0s8",
		},
		{
			ID:              2,
			NatType:         SNat,
			Dest:            "10.10.22.0/24",
			Source:          "192.168.2.2-192.168.2.23",
			DestPort:        "80-99",
			SourcePort:      "80",
			TargeIP:         "192.168.23.198",
			OutputInterface: "",
		},
		{
			ID:              3,
			NatType:         DNat,
			Dest:            "10.10.22.0/24",
			Source:          "192.168.2.2-192.168.2.23",
			DestPort:        "80-89",
			SourcePort:      "80",
			TargeIP:         "192.168.23.198",
			OutputInterface: "",
		},
	}
	nftis.ChangeNats(nats)
	err = nftis.Trigger()
	if err != nil {
		t.Error(err)
		return
	}
	err = nftis.Flush()
	if err != nil {
		t.Error(err)
	}
	nftis.Close()
}
