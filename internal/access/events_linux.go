//go:build linux

package access

import (
	"context"
	"errors"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nfnlgrpConntrackDestroy — группа событий удаления записей conntrack.
const nfnlgrpConntrackDestroy = 3

// ListenDestroy получает события удаления записей conntrack (с итоговыми
// счётчиками) и передаёт их в onGone, пока не отменён ctx. Так видны и
// соединения короче интервала опроса: например, отказ (RST в ответ на SYN) —
// ядро удаляет такую запись сразу.
func ListenDestroy(ctx context.Context, onGone func(Flow), onErr func(error)) error {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return err
	}
	if err := c.JoinGroup(nfnlgrpConntrackDestroy); err != nil {
		c.Close()
		return err
	}
	// Всплеск удалений не должен переполнять буфер (ENOBUFS — потеря событий;
	// пропущенное подберёт опрос таблицы).
	_ = c.SetReadBuffer(4 << 20)
	go func() {
		<-ctx.Done()
		_ = c.SetDeadline(time.Now())
	}()
	go func() {
		defer c.Close()
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
				if int(m.Header.Type) != msgCtDelete {
					continue
				}
				if f, err := parseFlow(m.Data); err == nil {
					onGone(f)
				}
			}
		}
	}()
	return nil
}
