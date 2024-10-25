package nftfilter

import "testing"

func TestNft(t *testing.T) {
	t.Log("nft test")
	nftis, err := NewNftFilter()
	if err != nil {
		t.Error(err)
	}
	var nats Nats = []Nat{}
	nftis.ChangeNats(nats)
	err = nftis.Trigger()
	if err != nil {
		t.Error(err)
	}
	err = nftis.Flush()
	if err != nil {
		t.Error(err)
	}
	nftis.Close()
}
