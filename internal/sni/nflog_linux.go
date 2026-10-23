//go:build linux

package sni

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nfnetlink_log (linux/netfilter/nfnetlink_log.h).
const (
	nfnlSubsysULOG  = 4
	nfulnlMsgPacket = 0
	nfulnlMsgConfig = 1

	nfulaCfgCmd  = 1
	nfulaCfgMode = 2
	nfulaPayload = 9

	nfulnlCfgCmdBind        = 1
	nfulnlCopyPacket        = 2
	nfgenmsgLen             = 4
	copyRange        uint32 = 2048
)

// Listen читает пакеты группы NFLOG group, собирает ClientHello и передаёт
// найденные имена в onName, пока не отменён ctx.
func Listen(ctx context.Context, group uint16, onName func(Conn, string), onErr func(error)) error {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return err
	}
	if err := config(c, group, []netlink.Attribute{{Type: nfulaCfgCmd, Data: []byte{nfulnlCfgCmdBind}}}); err != nil {
		c.Close()
		return err
	}
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, copyRange)
	mode[4] = nfulnlCopyPacket
	if err := config(c, group, []netlink.Attribute{{Type: nfulaCfgMode, Data: mode}}); err != nil {
		c.Close()
		return err
	}
	_ = c.SetReadBuffer(2 << 20)
	go func() {
		<-ctx.Done()
		_ = c.SetDeadline(time.Now())
	}()
	a := NewAssembler(nil)
	go func() {
		defer c.Close()
		last := time.Now()
		for ctx.Err() == nil {
			msgs, err := c.Receive()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !errors.Is(err, unix.ENOBUFS) {
					onErr(err)
					time.Sleep(time.Second)
				}
				continue
			}
			for _, m := range msgs {
				if m.Header.Type != nfnlSubsysULOG<<8|nfulnlMsgPacket {
					continue
				}
				if s, ok := ParseIPv4TCP(payload(m.Data)); ok {
					if name, ok := a.Add(s); ok {
						onName(s.Conn, name)
					}
				}
			}
			if time.Since(last) > pendingTTL {
				a.Expire()
				last = time.Now()
			}
		}
	}()
	return nil
}

// config — сообщение настройки группы.
func config(c *netlink.Conn, group uint16, attrs []netlink.Attribute) error {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return err
	}
	hdr := make([]byte, nfgenmsgLen)
	hdr[0] = unix.AF_UNSPEC
	binary.BigEndian.PutUint16(hdr[2:], group)
	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysULOG<<8 | nfulnlMsgConfig),
			Flags: netlink.Request | netlink.Acknowledge},
		Data: append(hdr, b...),
	})
	return err
}

// payload — пакет IP из сообщения NFLOG.
func payload(data []byte) []byte {
	if len(data) < nfgenmsgLen {
		return nil
	}
	ad, err := netlink.NewAttributeDecoder(data[nfgenmsgLen:])
	if err != nil {
		return nil
	}
	for ad.Next() {
		if ad.Type() == nfulaPayload {
			return ad.Bytes()
		}
	}
	return nil
}
