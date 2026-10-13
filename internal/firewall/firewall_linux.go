//go:build linux

package firewall

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Apply приводит таблицу router_service к Spec одной транзакцией netlink:
// правила и vpn_static заменяются целиком, а содержимое vpn_dynamic
// (адреса, узнанные из DNS) сохраняется — reload не сбрасывает выученное.
// Если схема существующей таблицы несовместима (например, сменился таймаут
// set'а), таблица пересоздаётся; recreated=true сообщает об этом.
func Apply(c *nftables.Conn, s Spec) (recreated bool, err error) {
	if err := s.Validate(); err != nil {
		return false, err
	}
	exists := tableExists(c)
	if exists && !setsCompatible(c, s) {
		// Параметры set'ов изменились (например, таймаут vpn_dynamic): не все
		// ядра умеют обновлять их на месте, поэтому пересоздаём таблицу.
		c.DelTable(table())
		recreated = true
	}
	build(c, s)
	if err := c.Flush(); err == nil {
		return recreated, nil
	} else if !exists || recreated {
		return false, fmt.Errorf("применение правил nftables: %w", err)
	}
	// Запасной путь: снести таблицу и создать заново в одной транзакции.
	c.DelTable(table())
	build(c, s)
	if err := c.Flush(); err != nil {
		return false, fmt.Errorf("пересоздание таблицы %s: %w", TableName, err)
	}
	return true, nil
}

// setsCompatible сверяет параметры существующих set'ов со Spec.
func setsCompatible(c *nftables.Conn, s Spec) bool {
	sets, err := c.GetSets(table())
	if err != nil {
		return false
	}
	var static, dynamic bool
	for _, set := range sets {
		switch set.Name {
		case SetStatic:
			static = set.Interval && !set.HasTimeout
		case SetDynamic:
			dynamic = set.HasTimeout && set.Timeout == s.DynamicTimeout && !set.Interval
		}
	}
	return static && dynamic
}

// Remove удаляет таблицу router_service (аналог очистки правил в stop bash-версии).
func Remove(c *nftables.Conn) error {
	if !tableExists(c) {
		return nil
	}
	c.DelTable(table())
	return c.Flush()
}

func table() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
}

func tableExists(c *nftables.Conn) bool {
	ts, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return false
	}
	for _, t := range ts {
		if t.Name == TableName {
			return true
		}
	}
	return false
}

// build ставит в очередь Conn все операции для Spec (без Flush).
func build(c *nftables.Conn, s Spec) {
	t := c.AddTable(table())

	static := &nftables.Set{Table: t, Name: SetStatic, KeyType: nftables.TypeIPAddr, Interval: true}
	dynamic := &nftables.Set{Table: t, Name: SetDynamic, KeyType: nftables.TypeIPAddr,
		HasTimeout: true, Timeout: s.DynamicTimeout}
	// Ошибки AddSet возможны только при неверных аргументах (тип ключа);
	// настоящие ошибки ядра придут из Flush.
	_ = c.AddSet(static, nil)
	_ = c.AddSet(dynamic, nil)
	c.FlushSet(static)
	if els := intervalElements(mergePrefixes(s.Static)); len(els) > 0 {
		_ = c.SetAddElements(static, els)
	}

	pre := c.AddChain(&nftables.Chain{Name: chainPrerouting, Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	mangle := c.AddChain(&nftables.Chain{Name: chainMangle, Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle})
	post := c.AddChain(&nftables.Chain{Name: chainPostroute, Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
	policy := nftables.ChainPolicyAccept
	fwd := c.AddChain(&nftables.Chain{Name: chainForward, Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &policy})
	for _, ch := range []*nftables.Chain{pre, mangle, post, fwd} {
		c.FlushChain(ch)
	}
	rule := func(ch *nftables.Chain, parts ...[]expr.Any) {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: concat(parts...)})
	}
	sets := []*nftables.Set{static, dynamic}

	if !s.Bypass {
		switch s.Mode {
		case ModeRedirect:
			// TCP с LAN к адресам из списков → локальный слушатель туннеля.
			for _, set := range sets {
				rule(pre, ifaceIn(s.Iface), l4proto(unix.IPPROTO_TCP), daddrIn(set),
					counter(), redirectTo(s.RedirectPort))
			}
		case ModeTProxy:
			// Пакеты уже перехваченных соединений (сокет слушателя прозрачный).
			rule(mangle, l4proto(unix.IPPROTO_TCP), socketTransparent(), setMark(Mark), verdict(expr.VerdictAccept))
			if s.QUICReject {
				// QUIC не перехватываем — его отклонит forward-цепочка ниже.
				rule(mangle, ifaceIn(s.Iface), l4proto(unix.IPPROTO_UDP), dport(443), verdict(expr.VerdictReturn))
			}
			for _, set := range sets {
				for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
					rule(mangle, ifaceIn(s.Iface), l4proto(proto), daddrIn(set),
						counter(), tproxyTo(s.RedirectPort), setMark(Mark), verdict(expr.VerdictAccept))
				}
			}
			// Слушателя нет (туннель упал): tproxy не срабатывает и пакет ушёл бы
			// напрямую. Помечаем его всё равно — он будет доставлен локально,
			// где клиент получит RST / port unreachable (VPN_FAILOVER=closed).
			for _, set := range sets {
				for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
					rule(mangle, ifaceIn(s.Iface), l4proto(proto), daddrIn(set), setMark(Mark))
				}
			}
		case ModeRoute:
			// Решение принимается на первом пакете соединения и запоминается
			// в ct mark: истечение записи в vpn_dynamic не рвёт соединение.
			for _, set := range sets {
				rule(mangle, ifaceIn(s.Iface), ctStateNew(), daddrIn(set), counter(), setCtMark(Mark))
			}
			// Только для пакетов из LAN: ответы из туннеля несут тот же ct mark,
			// и с fwmark они ушли бы обратно в туннель.
			rule(mangle, ifaceIn(s.Iface), ctMarkIs(Mark), setMark(Mark))
		}
	}

	// NAT для клиентов LAN наружу (тот же интерфейс — у RPi один порт;
	// в режиме route — и в интерфейс туннеля).
	rule(post, addrInPrefix(offSaddr, s.LAN, true), addrInPrefix(offDaddr, s.LAN, false),
		counter(), []expr.Any{&expr.Masq{}})

	if s.QUICReject {
		// QUIC к адресам из списков отклоняется: браузер сразу уходит на TCP,
		// который идёт через туннель.
		for _, set := range sets {
			rule(fwd, ifaceIn(s.Iface), l4proto(unix.IPPROTO_UDP), dport(443), daddrIn(set),
				counter(), rejectPortUnreachable())
		}
	}
	if s.Mode == ModeRoute {
		// MTU туннеля меньше, чем у клиентов: без ограничения MSS большие
		// TCP-пакеты теряются и соединения «зависают».
		rule(fwd, ifaceOut(s.Tun), l4proto(unix.IPPROTO_TCP), tcpSyn(), mssClampToPMTU())
	}
}

// intervalElements превращает диапазоны в элементы interval-set так же,
// как nft: [first, last+1) с флагом конца интервала, плюс начальный
// элемент-«дыра» 0.0.0.0, если первый диапазон не начинается с нуля.
func intervalElements(rs []ipRange) []nftables.SetElement {
	if len(rs) == 0 {
		return nil
	}
	var els []nftables.SetElement
	if rs[0].first != 0 {
		els = append(els, nftables.SetElement{Key: []byte{0, 0, 0, 0}, IntervalEnd: true})
	}
	for _, r := range rs {
		els = append(els, nftables.SetElement{Key: u32ToAddr(r.first).AsSlice()})
		if r.last != ^uint32(0) {
			els = append(els, nftables.SetElement{Key: u32ToAddr(r.last + 1).AsSlice(), IntervalEnd: true})
		}
	}
	return els
}

// --- выражения ---

const (
	offSaddr = 12 // смещение адреса источника в заголовке IPv4
	offDaddr = 16 // смещение адреса назначения
)

func concat(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func ifname(n string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, n)
	return b
}

func ifaceIn(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

func l4proto(p byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{p}},
	}
}

func dport(p uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(p)},
	}
}

func daddrIn(s *nftables.Set) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offDaddr, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID},
	}
}

// addrInPrefix — адрес (по смещению off) входит (in=true) или не входит в подсеть.
func addrInPrefix(off uint32, p netip.Prefix, in bool) []expr.Any {
	m := ^uint32(0) << (32 - p.Bits())
	if p.Bits() == 0 {
		m = 0
	}
	mask := binaryutil.BigEndian.PutUint32(m)
	op := expr.CmpOpEq
	if !in {
		op = expr.CmpOpNeq
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: op, Register: 1, Data: p.Masked().Addr().AsSlice()},
	}
}

func counter() []expr.Any { return []expr.Any{&expr.Counter{}} }

func redirectTo(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Redir{RegisterProtoMin: 1},
	}
}

func ifaceOut(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

func verdict(k expr.VerdictKind) []expr.Any { return []expr.Any{&expr.Verdict{Kind: k}} }

func setMark(m uint32) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(m)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}

func socketTransparent() []expr.Any {
	return []expr.Any{
		&expr.Socket{Key: expr.SocketKeyTransparent, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(1)},
	}
}

func tproxyTo(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.TProxy{Family: unix.NFPROTO_IPV4, TableFamily: unix.NFPROTO_IPV4, RegPort: 1},
	}
}

func ctStateNew() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW), Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

func setCtMark(m uint32) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(m)},
		&expr.Ct{Key: expr.CtKeyMARK, SourceRegister: true, Register: 1},
	}
}

func ctMarkIs(m uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(m)},
	}
}

// tcpSyn — tcp flags syn.
func tcpSyn() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x02}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0}},
	}
}

// mssClampToPMTU — tcp option maxseg size set rt mtu.
func mssClampToPMTU() []expr.Any {
	return []expr.Any{
		&expr.Rt{Register: 1, Key: expr.RtTCPMSS},
		&expr.Byteorder{SourceRegister: 1, DestRegister: 1, Op: expr.ByteorderHton, Len: 2, Size: 2},
		&expr.Exthdr{SourceRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
	}
}

func rejectPortUnreachable() []expr.Any {
	return []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: 3 /* port unreachable */}}
}
