//go:build linux

package localclient

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/fsutil"
)

// Up создаёт (или переиспользует) namespace сервиса и заново поднимает
// veth-пару: адрес RPi — l.HostIP(), адрес сервиса — l.ClientIP(), маршрут
// по умолчанию через RPi, DNS — dns (RPI5_IP, где слушает routerd).
// Существующий namespace не пересоздаётся: в нём могут оставаться процессы.
func Up(l config.LocalClient, dns netip.Addr) error {
	// Переключение namespace действует на поток, а не на процесс.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return fmt.Errorf("текущий network namespace: %w", err)
	}
	defer orig.Close()

	ns, err := netns.GetFromName(l.Name)
	if err == nil && !isNetns(ns) {
		// Файл есть, но namespace на нём не закреплён (например, остался после
		// сбоя) — создаём заново.
		ns.Close()
		if err := os.Remove(NetnsPath(l.Name)); err != nil {
			return fmt.Errorf("network namespace %s: %w", l.Name, err)
		}
		err = fs.ErrNotExist
	}
	if errors.Is(err, fs.ErrNotExist) {
		ns, err = netns.NewNamed(l.Name) // поток переключается в новый namespace
		if serr := netns.Set(orig); serr != nil {
			return fmt.Errorf("возврат в исходный network namespace: %w", serr)
		}
	}
	if err != nil {
		return fmt.Errorf("network namespace %s: %w", l.Name, err)
	}
	defer ns.Close()

	host, err := netlink.NewHandleAt(orig)
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer host.Close()
	inner, err := netlink.NewHandleAt(ns)
	if err != nil {
		return fmt.Errorf("netlink в %s: %w", l.Name, err)
	}
	defer inner.Close()

	// veth-пара пересоздаётся целиком: так не остаётся старых адресов и
	// половинок от прежнего запуска (удаление одной стороны удаляет обе).
	for _, h := range []struct {
		h    *netlink.Handle
		name string
	}{{host, l.Iface()}, {inner, PeerIface}} {
		if link, err := h.h.LinkByName(h.name); err == nil {
			if err := h.h.LinkDel(link); err != nil {
				return fmt.Errorf("удаление прежнего %s: %w", h.name, err)
			}
		}
	}
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: l.Iface()},
		PeerName:      PeerIface,
		PeerNamespace: netlink.NsFd(ns),
	}
	if err := host.LinkAdd(veth); err != nil {
		return fmt.Errorf("создание veth %s: %w", l.Iface(), err)
	}

	bits := l.Net.Bits()
	if err := linkUp(host, l.Iface(), l.HostIP(), bits); err != nil {
		return err
	}
	if lo, err := inner.LinkByName("lo"); err != nil {
		return fmt.Errorf("lo в %s: %w", l.Name, err)
	} else if err := inner.LinkSetUp(lo); err != nil {
		return fmt.Errorf("lo в %s: %w", l.Name, err)
	}
	if err := linkUp(inner, PeerIface, l.ClientIP(), bits); err != nil {
		return err
	}
	if err := inner.RouteReplace(&netlink.Route{Gw: net.IP(l.HostIP().AsSlice())}); err != nil {
		return fmt.Errorf("маршрут по умолчанию в %s: %w", l.Name, err)
	}
	return writeResolv(l.Name, dns)
}

// isNetns — дескриптор указывает на network namespace (nsfs), а не на
// обычный файл.
func isNetns(ns netns.NsHandle) bool {
	var st unix.Statfs_t
	return unix.Fstatfs(int(ns), &st) == nil && st.Type == unix.NSFS_MAGIC
}

// linkUp назначает адрес и поднимает интерфейс.
func linkUp(h *netlink.Handle, name string, a netip.Addr, bits int) error {
	link, err := h.LinkByName(name)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(bits, 32)}}
	if err := h.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("адрес %s/%d на %s: %w", a, bits, name, err)
	}
	if err := h.LinkSetUp(link); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// writeResolv записывает resolv.conf сервиса: DNS — routerd на RPi.
func writeResolv(name string, dns netip.Addr) error {
	path := ResolvPath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "# routerd local-client %s: DNS — routerd на RPi\nnameserver %s\n", name, dns)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return fsutil.Rename(tmp, path)
}

// Down убирает veth, namespace и resolv.conf сервиса. Отсутствующие части
// не считаются ошибкой: Down вызывается и для уже убранного сервиса.
func Down(name string) error {
	var errs []error
	if link, err := netlink.LinkByName(config.LocalIfacePrefix + name); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Errorf("удаление veth: %w", err))
		}
	}
	if _, err := os.Stat(NetnsPath(name)); err == nil {
		if err := netns.DeleteNamed(name); err != nil {
			errs = append(errs, fmt.Errorf("удаление network namespace %s: %w", name, err))
		}
	}
	if err := os.Remove(ResolvPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	_ = os.Remove(filepath.Dir(ResolvPath(name))) // только если пуст
	return errors.Join(errs...)
}
