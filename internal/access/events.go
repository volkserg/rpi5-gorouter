package access

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/mdlayher/netlink"
)

// Атрибуты ctnetlink (linux/netfilter/nfnetlink_conntrack.h).
const (
	ctaTupleOrig     = 1
	ctaTupleReply    = 2
	ctaProtoinfo     = 4
	ctaCountersOrig  = 9
	ctaCountersReply = 10

	ctaTupleIP    = 1
	ctaTupleProto = 2
	ctaIPv4Src    = 1
	ctaIPv4Dst    = 2
	ctaProtoNum   = 1
	ctaProtoSrc   = 2
	ctaProtoDst   = 3

	ctaCountersPackets = 1
	ctaCountersBytes   = 2

	ctaProtoinfoTCP      = 1
	ctaProtoinfoTCPState = 1

	// msgCtDelete — тип сообщения события удаления записи:
	// NFNL_SUBSYS_CTNETLINK<<8 | IPCTNL_MSG_CT_DELETE.
	msgCtDelete = 1<<8 | 2
	// nfgenmsgLen — заголовок nfnetlink перед атрибутами.
	nfgenmsgLen = 4
)

// parseFlow разбирает сообщение ctnetlink (событие удаления записи) в Flow.
func parseFlow(data []byte) (Flow, error) {
	var f Flow
	if len(data) < nfgenmsgLen {
		return f, errors.New("короткое сообщение ctnetlink")
	}
	ad, err := netlink.NewAttributeDecoder(data[nfgenmsgLen:])
	if err != nil {
		return f, err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaTupleOrig:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				nad.ByteOrder = binary.BigEndian
				return parseTuple(nad, &f)
			})
		case ctaCountersOrig:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				f.OrigPkts, f.OrigBytes = parseCounters(nad)
				return nil
			})
		case ctaCountersReply:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				f.ReplyPkts, f.ReplyBytes = parseCounters(nad)
				return nil
			})
		case ctaProtoinfo:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					if nad.Type() == ctaProtoinfoTCP {
						nad.Nested(func(tad *netlink.AttributeDecoder) error {
							for tad.Next() {
								if tad.Type() == ctaProtoinfoTCPState {
									f.TCPState = tad.Uint8()
								}
							}
							return nil
						})
					}
				}
				return nil
			})
		}
	}
	if err := ad.Err(); err != nil {
		return f, err
	}
	if !f.Src.IsValid() || !f.Dst.IsValid() {
		return f, errors.New("нет адресов IPv4 в записи")
	}
	return f, nil
}

func parseTuple(ad *netlink.AttributeDecoder, f *Flow) error {
	for ad.Next() {
		switch ad.Type() {
		case ctaTupleIP:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					a, ok := netip.AddrFromSlice(nad.Bytes())
					if !ok || !a.Is4() {
						continue
					}
					switch nad.Type() {
					case ctaIPv4Src:
						f.Src = a
					case ctaIPv4Dst:
						f.Dst = a
					}
				}
				return nil
			})
		case ctaTupleProto:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				nad.ByteOrder = binary.BigEndian
				for nad.Next() {
					switch nad.Type() {
					case ctaProtoNum:
						f.Proto = nad.Uint8()
					case ctaProtoSrc:
						f.SPort = nad.Uint16()
					case ctaProtoDst:
						f.DPort = nad.Uint16()
					}
				}
				return nil
			})
		}
	}
	return nil
}

func parseCounters(ad *netlink.AttributeDecoder) (pkts, bytes uint64) {
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaCountersPackets:
			pkts = ad.Uint64()
		case ctaCountersBytes:
			bytes = ad.Uint64()
		}
	}
	return pkts, bytes
}
