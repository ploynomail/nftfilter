package main

import "github.com/ploynomail/nftfilter"

func main() {
	nftis, err := nftfilter.NewNftFilter()
	if err != nil {
		panic(err)
	}
	var nats nftfilter.Nats = []nftfilter.Nat{
		{
			ID:              1,
			NatType:         nftfilter.SNat,
			Dest:            "192.168.23.73",
			Source:          "",
			DestPort:        "8000",
			SourcePort:      "",
			TargeIP:         "192.168.23.198",
			OutputInterface: "",
		},
	}
	nftis.ChangeNats(nats)
	err = nftis.Trigger()
	if err != nil {
		panic(err)
	}
	err = nftis.Flush()
	if err != nil {
		panic(err)
	}
	nftis.Close()
}
