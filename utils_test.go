package nftfilter

import (
	"testing"

	"github.com/google/nftables"
)

func TestHandlePortAndRange(t *testing.T) {
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "NatTable-test",
	}
	conn, err := nftables.New()
	defer conn.CloseLasting()

	conn.AddTable(table)

	if err != nil {
		t.Errorf("nftables.New failed, err: %v", err)
	}
	// portStr := "80"
	// newSet, err := HandlePortAndRange(table, portStr, conn)
	// if err != nil {
	// 	t.Errorf("HandlePortAndRange failed, err: %v", err)
	// }
	// if newSet != nil {
	// 	t.Logf("HandlePortAndRange success, newSet: %v, ID: %d", newSet, newSet.ID)
	// }
	// if err := conn.Flush(); err != nil {
	// 	t.Errorf("conn.Flush failed, err: %v", err)
	// }
}
