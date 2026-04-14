// Package nftconn provides a shared nftables connection and table management.
// All gametunnel nftables rules live in a single "ip gametunnel" table.
// The table is created lazily on first use and deleted on cleanup.
package nftconn

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	TableName = "gametunnel"
)

// Conn wraps a nftables.Conn with lazy table creation and shared chain management.
type Conn struct {
	mu    sync.Mutex
	nft   *nftables.Conn
	table *nftables.Table
}

// New creates a new nftables connection. Returns an error if the kernel does
// not support nftables netlink.
func New() (*Conn, error) {
	nft, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("create nftables conn: %w", err)
	}

	// Probe: try to list tables. If this fails, nftables is not available.
	if _, err := nft.ListTablesOfFamily(nftables.TableFamilyIPv4); err != nil {
		return nil, fmt.Errorf("nftables not available: %w", err)
	}

	return &Conn{nft: nft}, nil
}

// Table returns the shared ip gametunnel table, creating it if needed.
// Must be called under c.mu.
func (c *Conn) Table() *nftables.Table {
	if c.table == nil {
		c.table = c.nft.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   TableName,
		})
	}
	return c.table
}

// Lock acquires the mutex. Callers must call Unlock when done.
func (c *Conn) Lock()   { c.mu.Lock() }
func (c *Conn) Unlock() { c.mu.Unlock() }

// Flush sends all pending nftables operations atomically.
func (c *Conn) Flush() error {
	return c.nft.Flush()
}

// Raw returns the underlying nftables.Conn for direct operations.
// Callers must hold the lock.
func (c *Conn) Raw() *nftables.Conn { return c.nft }

// Cleanup deletes the entire gametunnel table. This removes all chains, rules,
// and sets in one atomic operation.
func (c *Conn) Cleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.table == nil {
		// Table might exist from a previous run; try to find it.
		tables, err := c.nft.ListTablesOfFamily(nftables.TableFamilyIPv4)
		if err != nil {
			return nil
		}
		for _, t := range tables {
			if t.Name == TableName {
				c.table = t
				break
			}
		}
		if c.table == nil {
			return nil // nothing to clean
		}
	}

	c.nft.DelTable(c.table)
	if err := c.nft.Flush(); err != nil {
		return fmt.Errorf("delete table %s: %w", TableName, err)
	}
	c.table = nil
	return nil
}

// --- Helper functions for building nftables expressions ---

// PortBytes converts a port number to 2 big-endian bytes for nftables set elements.
func PortBytes(port int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(port))
	return b
}

// SetMarkExprs returns expressions to unconditionally set packet mark to mark/mask.
// This replicates iptables -j MARK --set-xmark mark/mask.
// nftables equivalent: meta mark set meta mark & ~mask ^ mark_value
func SetMarkExprs(markVal, mask uint32) []expr.Any {
	return []expr.Any{
		// Load current mark
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		// Apply: reg1 = (reg1 AND NOT(mask)) XOR markVal
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^mask),
			Xor:            binaryutil.NativeEndian.PutUint32(markVal),
		},
		// Write back to meta mark
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// MatchDportInSet returns expressions that match the transport-layer destination
// port against a named set. Equivalent to: th dport @<setName>
func MatchDportInSet(setName string, setID uint32) []expr.Any {
	return []expr.Any{
		// Load 2 bytes from transport header offset 2 (destination port)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		// Lookup in set
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        setName,
			SetID:          setID,
		},
	}
}

// MatchIIFName returns an expression that matches the input interface name.
func MatchIIFName(iface string) []expr.Any {
	ifBytes := ifnameBytes(iface)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifBytes,
		},
	}
}

// MatchOIFName returns an expression that matches the output interface name.
func MatchOIFName(iface string) []expr.Any {
	ifBytes := ifnameBytes(iface)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifBytes,
		},
	}
}

// MatchProto returns an expression matching the L4 protocol (6=TCP, 17=UDP).
func MatchProto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
	}
}

// MatchDport returns expressions matching a specific destination port.
func MatchDport(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
	}
}

// AcceptVerdict returns an expression that accepts the packet.
func AcceptVerdict() *expr.Verdict {
	return &expr.Verdict{Kind: expr.VerdictAccept}
}

// ReturnVerdict returns an expression that returns from the current chain.
func ReturnVerdict() *expr.Verdict {
	return &expr.Verdict{Kind: expr.VerdictReturn}
}

// DNATExprs returns expressions that DNAT to the given IP:port.
// The caller must ensure this is used in a nat chain.
func DNATExprs(destIP net.IP, destPort uint16) []expr.Any {
	ip4 := destIP.To4()
	if ip4 == nil {
		ip4 = destIP
	}
	return []expr.Any{
		// Load dest IP into register 1
		&expr.Immediate{
			Register: 1,
			Data:     ip4,
		},
		// Load dest port into register 2
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(destPort),
		},
		// NAT
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

// ConnmarkSetExprs returns expressions that set the connmark (ct mark).
// Equivalent to: ct mark set mark/mask
func ConnmarkSetExprs(markVal, mask uint32) []expr.Any {
	return []expr.Any{
		// Load current connmark
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		// Apply: reg1 = (reg1 AND NOT(mask)) XOR markVal
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^mask),
			Xor:            binaryutil.NativeEndian.PutUint32(markVal),
		},
		// Write back to ct mark
		&expr.Ct{
			Key:            expr.CtKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// MatchConnmark returns expressions that match the connmark value.
// Equivalent to: ct mark & mask == value
func MatchConnmark(value, mask uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(mask),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(value),
		},
	}
}

// SimpleConnmarkRestore returns expressions for restoring connmark to packet mark.
// This is a simplified version: meta mark set ct mark & mask
// It just copies the masked bits from ct mark to packet mark.
func SimpleConnmarkRestore(mask uint32) []expr.Any {
	return []expr.Any{
		// Load ct mark
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		// Mask it
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(mask),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		// Set packet mark (this overwrites the entire mark; for exact CONNMARK
		// --restore-mark behavior with separate nfmask/ctmask, a more complex
		// sequence would be needed, but for our use case where mask is the same
		// and we only care about those bits, this suffices.)
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// ifnameBytes converts an interface name to a null-terminated 16-byte array
// matching the IFNAMSIZ kernel constant.
func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}
