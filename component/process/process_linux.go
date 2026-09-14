package process

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unsafe"

	"github.com/metacubex/mihomo/log"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	SOCK_DIAG_BY_FAMILY  = 20
	inetDiagRequestSize  = int(unsafe.Sizeof(inetDiagRequest{}))
	inetDiagResponseSize = int(unsafe.Sizeof(inetDiagResponse{}))
	recentPIDLimit       = 8
)

type recentPIDs struct {
	mu   sync.RWMutex
	pids [recentPIDLimit]string
	len  int
}

var recentProcessPIDs sync.Map // map[uint32]*recentPIDs

type inetDiagRequest struct {
	Family   byte
	Protocol byte
	Ext      byte
	Pad      byte
	States   uint32

	SrcPort [2]byte
	DstPort [2]byte
	Src     [16]byte
	Dst     [16]byte
	If      uint32
	Cookie  [2]uint32
}

type inetDiagResponse struct {
	Family  byte
	State   byte
	Timer   byte
	ReTrans byte

	SrcPort [2]byte
	DstPort [2]byte
	Src     [16]byte
	Dst     [16]byte
	If      uint32
	Cookie  [2]uint32

	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	INode   uint32
}

func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
	if !ip.IsValid() || srcPort < 0 || srcPort > 65535 {
		return 0, "", ErrNotFound
	}
	return findProcessNameByAddr(network, netip.AddrPortFrom(ip.Unmap(), uint16(srcPort)), netip.AddrPort{}, nil)
}

func findProcessNameByAddr(network string, src, dst netip.AddrPort, matcher ProcessMatcher) (uint32, string, error) {
	if !src.IsValid() {
		return 0, "", ErrNotFound
	}
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	if dst.IsValid() {
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}

	var (
		uid   uint32
		inode uint32
		err   error
	)
	if canUseExactSocketLookup(src, dst) {
		uid, inode, err = resolveSocketByNetlinkExact(network, src, dst)
	}
	if err != nil || inode == 0 {
		uid, inode, err = resolveSocketByNetlink(network, src.Addr(), int(src.Port()))
	}
	if runtime.GOOS == "android" {
		// on Android (especially recent releases), netlink INET_DIAG can fail or return UID 0 / empty process info for some apps
		// so trying fallback to resolve /proc/net/{tcp,tcp6,udp,udp6}
		if err != nil {
			uid, inode, err = resolveSocketByProcFS(network, src.Addr(), int(src.Port()))
		} else if uid == 0 {
			pUID, pInode, pErr := resolveSocketByProcFS(network, src.Addr(), int(src.Port()))
			if pErr == nil && pUID != 0 {
				uid, inode, err = pUID, pInode, nil
			}
		}
	}
	if err != nil || inode == 0 {
		if err == nil {
			err = ErrNotFound
		}
		return 0, "", err
	}
	if runtime.GOOS == "android" && matcher != nil && uid != 0 {
		// Android PROCESS-NAME rules match PackageManager's cached UID-to-package
		// mapping, not /proc/<pid>/exe (normally app_process). Reject packages
		// absent from the active rules before scanning any fd directory. If the
		// package cache is temporarily unavailable, preserve the old full lookup.
		if matched, resolved := matchPackageNameByUID(uid, matcher); resolved {
			if !matched {
				return uid, "", ErrNotFound
			}
			matcher = nil // candidate hit: supplement the package with PID/path
		} else {
			matcher = nil
		}
	}
	pp, err := resolveProcessNameByProcSearch(inode, uid, matcher)
	if runtime.GOOS == "android" {
		// if inode-based /proc/<pid>/fd resolution fails but UID is known,
		// fall back to resolving the process/package name by UID (typical on Android where all app processes share one UID).
		if err != nil && uid != 0 {
			pp, err = resolveProcessNameByUID(uid)
		}
	}
	return uid, pp, err
}

func canUseExactSocketLookup(src, dst netip.AddrPort) bool {
	return src.IsValid() && dst.IsValid() && dst.Port() != 0 && src.Addr().BitLen() == dst.Addr().BitLen()
}

func resolveSocketByNetlinkExact(network string, src, dst netip.AddrPort) (uint32, uint32, error) {
	if !canUseExactSocketLookup(src, dst) {
		return 0, 0, ErrNotFound
	}
	request := &inetDiagRequest{
		States: 0xffffffff,
		Cookie: [2]uint32{0xffffffff, 0xffffffff},
	}

	if src.Addr().Is4() {
		request.Family = unix.AF_INET
	} else {
		request.Family = unix.AF_INET6
	}

	isTCP := strings.HasPrefix(network, "tcp")
	switch {
	case isTCP:
		request.Protocol = unix.IPPROTO_TCP
		setInetDiagEndpoints(request, src, dst)
	case strings.HasPrefix(network, "udp"):
		request.Protocol = unix.IPPROTO_UDP
		// udp_diag_dump_one expects the incoming packet direction (remote to
		// local), historically reversed from inet_diag response fields.
		setInetDiagEndpoints(request, dst, src)
	default:
		return 0, 0, ErrInvalidNetwork
	}

	messages, err := executeInetDiag(request, netlink.Request)
	if err != nil {
		return 0, 0, err
	}
	for _, msg := range messages {
		if len(msg.Data) < inetDiagResponseSize {
			continue
		}
		response := (*inetDiagResponse)(unsafe.Pointer(&msg.Data[0]))
		if response.INode == 0 {
			continue
		}
		local, ok := inetDiagAddrPort(response.Family, response.Src, response.SrcPort)
		if !ok || local.Port() != src.Port() {
			continue
		}
		localIP := local.Addr().Unmap()
		if localIP != src.Addr() && (isTCP || !localIP.IsUnspecified()) {
			continue
		}
		if isTCP {
			remote, ok := inetDiagAddrPort(response.Family, response.Dst, response.DstPort)
			if !ok || remote != dst {
				continue
			}
		} else {
			remote, ok := inetDiagAddrPort(response.Family, response.Dst, response.DstPort)
			if !ok || (remote.Port() != 0 && remote != dst) {
				continue
			}
		}
		return response.UID, response.INode, nil
	}
	return 0, 0, ErrNotFound
}

func setInetDiagEndpoints(request *inetDiagRequest, src, dst netip.AddrPort) {
	copy(request.Src[:], src.Addr().AsSlice())
	copy(request.Dst[:], dst.Addr().AsSlice())
	binary.BigEndian.PutUint16(request.SrcPort[:], src.Port())
	binary.BigEndian.PutUint16(request.DstPort[:], dst.Port())
}

func inetDiagAddrPort(family byte, rawIP [16]byte, rawPort [2]byte) (netip.AddrPort, bool) {
	var ip netip.Addr
	switch family {
	case unix.AF_INET:
		var addr [4]byte
		copy(addr[:], rawIP[:4])
		ip = netip.AddrFrom4(addr)
	case unix.AF_INET6:
		ip = netip.AddrFrom16(rawIP).Unmap()
	default:
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(rawPort[:])), true
}

func executeInetDiag(request *inetDiagRequest, flags netlink.HeaderFlags) ([]netlink.Message, error) {
	conn, err := netlink.Dial(unix.NETLINK_INET_DIAG, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  SOCK_DIAG_BY_FAMILY,
			Flags: flags,
		},
		Data: (*(*[inetDiagRequestSize]byte)(unsafe.Pointer(request)))[:],
	})
}

func resolveSocketByNetlink(network string, ip netip.Addr, srcPort int) (uint32, uint32, error) {
	request := &inetDiagRequest{
		States: 0xffffffff,
		Cookie: [2]uint32{0xffffffff, 0xffffffff},
	}

	if ip.Is4() {
		request.Family = unix.AF_INET
	} else {
		request.Family = unix.AF_INET6
	}

	if strings.HasPrefix(network, "tcp") {
		request.Protocol = unix.IPPROTO_TCP
	} else if strings.HasPrefix(network, "udp") {
		request.Protocol = unix.IPPROTO_UDP
	} else {
		return 0, 0, ErrInvalidNetwork
	}

	copy(request.Src[:], ip.AsSlice())

	binary.BigEndian.PutUint16(request.SrcPort[:], uint16(srcPort))

	messages, err := executeInetDiag(request, netlink.Request|netlink.Dump)
	if err != nil {
		return 0, 0, err
	}

	for _, msg := range messages {
		if len(msg.Data) < inetDiagResponseSize {
			continue
		}

		response := (*inetDiagResponse)(unsafe.Pointer(&msg.Data[0]))
		if response.INode == 0 {
			continue
		}

		// check src port
		if binary.BigEndian.Uint16(response.SrcPort[:]) != uint16(srcPort) {
			continue
		}

		// check src IP
		var src netip.Addr
		switch response.Family {
		case unix.AF_INET:
			var a [4]byte
			copy(a[:], response.Src[:4])
			src = netip.AddrFrom4(a)
		case unix.AF_INET6:
			var a [16]byte
			copy(a[:], response.Src[:])
			src = netip.AddrFrom16(a).Unmap()
		default:
			continue
		}
		if src != ip.Unmap() {
			continue
		}

		return response.UID, response.INode, nil
	}

	return 0, 0, ErrNotFound
}

func resolveProcessNameByProcSearch(inode, uid uint32, matcher ProcessMatcher) (string, error) {
	debug := log.Enabled(log.DEBUG)
	candidates, fdScans := 0, 0
	finalPID := ""
	if debug {
		defer func() {
			reason := "socket_inode_not_found"
			if finalPID != "" {
				reason = "socket_inode_matched"
			}
			log.Fields(log.DEBUG, map[string]string{"subsystem": "process", "event": "pid_filter", "candidate_count": strconv.Itoa(candidates), "fd_filter_count": strconv.Itoa(fdScans), "pid": finalPID, "reason": reason}, "Process uid=%d inode=%d candidate PIDs=%d FD scans=%d final PID=%s", uid, inode, candidates, fdScans, finalPID)
		}()
	}
	buffer := make([]byte, unix.PathMax)
	socket := fmt.Appendf(nil, "socket:[%d]", inode)

	// Most applications create many connections from the same process. Try the
	// recently successful PIDs for this UID before scanning every /proc entry.
	// Each candidate is still verified against the current socket inode, so PID
	// reuse and stale cache entries cannot produce a false match.
	recentPIDs := loadRecentProcessPIDs(uid)
	for _, pid := range recentPIDs {
		processPath := filepath.Join("/proc", pid)
		info, err := os.Stat(processPath)
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}
		name, candidate, err := matchProcessCandidate(processPath, matcher)
		if debug {
			candidates++
		}
		if err != nil || !candidate {
			continue
		}
		name, matched, err := findProcessNameInPath(processPath, name, socket, buffer)
		if debug {
			fdScans++
		}
		if err != nil {
			if isTransientProcError(err) {
				continue
			}
			return "", err
		}
		if matched {
			finalPID = pid
			rememberProcessPID(uid, pid)
			return name, nil
		}
	}

	files, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	for _, f := range files {
		if !f.IsDir() || !isPid(f.Name()) {
			continue
		}
		if containsPID(recentPIDs, f.Name()) {
			continue
		}

		info, err := f.Info()
		if err != nil {
			continue
		}
		if info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}

		processPath := filepath.Join("/proc", f.Name())
		name, candidate, err := matchProcessCandidate(processPath, matcher)
		if debug {
			candidates++
		}
		if err != nil || !candidate {
			continue
		}
		name, matched, err := findProcessNameInPath(processPath, name, socket, buffer)
		if debug {
			fdScans++
		}
		if err != nil {
			if isTransientProcError(err) {
				continue
			}
			return "", err
		}
		if matched {
			finalPID = f.Name()
			rememberProcessPID(uid, f.Name())
			return name, nil
		}
	}

	return "", fmt.Errorf("process of uid(%d),inode(%d) not found", uid, inode)
}

func isTransientProcError(err error) bool {
	return os.IsNotExist(err) || os.IsPermission(err)
}

func containsPID(pids []string, pid string) bool {
	return slices.Contains(pids, pid)
}

func matchProcessCandidate(processPath string, matcher ProcessMatcher) (string, bool, error) {
	if matcher == nil {
		return "", true, nil
	}
	name, err := os.Readlink(filepath.Join(processPath, "exe"))
	if err != nil {
		return "", false, err
	}
	return name, matcher.MatchProcess(name), nil
}

func findProcessNameInPath(processPath, processName string, socket, buffer []byte) (string, bool, error) {
	fdPath := filepath.Join(processPath, "fd")
	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return "", false, nil
	}

	for _, fd := range fds {
		n, err := unix.Readlink(filepath.Join(fdPath, fd.Name()), buffer)
		if err != nil || !bytes.Equal(buffer[:n], socket) {
			continue
		}

		if runtime.GOOS == "android" {
			cmdline, err := os.ReadFile(path.Join(processPath, "cmdline"))
			if err != nil {
				return "", false, err
			}
			return splitCmdline(cmdline), true, nil
		}

		if processName != "" {
			return processName, true, nil
		}
		name, err := os.Readlink(filepath.Join(processPath, "exe"))
		return name, err == nil, err
	}

	return "", false, nil
}

func loadRecentProcessPIDs(uid uint32) []string {
	value, ok := recentProcessPIDs.Load(uid)
	if !ok {
		return nil
	}
	recent := value.(*recentPIDs)
	recent.mu.RLock()
	defer recent.mu.RUnlock()
	pids := make([]string, recent.len)
	copy(pids, recent.pids[:recent.len])
	return pids
}

func rememberProcessPID(uid uint32, pid string) {
	value, _ := recentProcessPIDs.LoadOrStore(uid, &recentPIDs{})
	recent := value.(*recentPIDs)
	recent.mu.Lock()
	defer recent.mu.Unlock()

	index := recent.len
	for i := 0; i < recent.len; i++ {
		if recent.pids[i] == pid {
			index = i
			break
		}
	}
	if index == 0 && recent.len > 0 {
		return
	}
	if index == recent.len && recent.len < recentPIDLimit {
		recent.len++
	}
	if index >= recentPIDLimit {
		index = recentPIDLimit - 1
	}
	copy(recent.pids[1:index+1], recent.pids[:index])
	recent.pids[0] = pid
}

// resolveProcessNameByUID returns a process name for any process with uid.
// On Android all processes of one app share the same UID; used when inode
// lookup fails (socket closed / TIME_WAIT).
func resolveProcessNameByUID(uid uint32) (string, error) {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	for _, f := range files {
		if !f.IsDir() || !isPid(f.Name()) {
			continue
		}

		info, err := f.Info()
		if err != nil {
			continue
		}
		if info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}

		processPath := filepath.Join("/proc", f.Name())
		if runtime.GOOS == "android" {
			cmdline, err := os.ReadFile(path.Join(processPath, "cmdline"))
			if err != nil {
				continue
			}
			if name := splitCmdline(cmdline); name != "" {
				return name, nil
			}
		} else {
			if exe, err := os.Readlink(filepath.Join(processPath, "exe")); err == nil {
				return exe, nil
			}
		}
	}

	return "", fmt.Errorf("no process found with uid %d", uid)
}

func splitCmdline(cmdline []byte) string {
	cmdline = bytes.Trim(cmdline, " ")

	idx := bytes.IndexFunc(cmdline, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	})

	if idx == -1 {
		return filepath.Base(string(cmdline))
	}
	return filepath.Base(string(cmdline[:idx]))
}

func isPid(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsDigit(r)
	}) == -1
}

// resolveSocketByProcFS finds UID and inode from /proc/net/{tcp,tcp6,udp,udp6}.
// In TUN mode metadata sourceIP is often the gateway (e.g. fake-ip range), not
// the socket's real local address; we match by local port first and prefer
// exact IP+port when it matches.
func resolveSocketByProcFS(network string, ip netip.Addr, srcPort int) (uint32, uint32, error) {
	var proto string
	switch {
	case strings.HasPrefix(network, "tcp"):
		proto = "tcp"
	case strings.HasPrefix(network, "udp"):
		proto = "udp"
	default:
		return 0, 0, ErrInvalidNetwork
	}

	targetPort := uint16(srcPort)
	unmapped := ip.Unmap()
	files := []string{"/proc/net/" + proto, "/proc/net/" + proto + "6"}

	var bestUID, bestInode uint32
	found := false

	for _, path := range files {
		isV6 := strings.HasSuffix(path, "6")

		var matchIP netip.Addr
		if unmapped.Is4() {
			if isV6 {
				matchIP = netip.AddrFrom16(unmapped.As16())
			} else {
				matchIP = unmapped
			}
		} else {
			if !isV6 {
				continue
			}
			matchIP = unmapped
		}

		uid, inode, exact, err := searchProcNetFileByPort(path, matchIP, targetPort)
		if err != nil {
			continue
		}

		if exact {
			return uid, inode, nil
		}

		if !found || (bestUID == 0 && uid != 0) {
			bestUID = uid
			bestInode = inode
			found = true
		}
	}

	if found {
		return bestUID, bestInode, nil
	}
	return 0, 0, ErrNotFound
}

// searchProcNetFileByPort scans /proc/net/* for local_address matching targetPort.
// Exact IP+port wins; else port-only (skips inode==0 entries used by TIME_WAIT).
func searchProcNetFileByPort(path string, targetIP netip.Addr, targetPort uint16) (uid, inode uint32, exact bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false, err
	}
	defer f.Close()

	isV6 := strings.HasSuffix(path, "6")
	scanner := bufio.NewScanner(f)

	if !scanner.Scan() {
		return 0, 0, false, ErrNotFound
	}

	var bestUID, bestInode uint32
	found := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		lineIP, linePort, parseErr := parseHexAddrPort(fields[1], isV6)
		if parseErr != nil {
			continue
		}
		if linePort != targetPort {
			continue
		}

		lineUID, parseErr := strconv.ParseUint(fields[7], 10, 32)
		if parseErr != nil {
			continue
		}
		lineInode, parseErr := strconv.ParseUint(fields[9], 10, 32)
		if parseErr != nil {
			continue
		}

		if lineIP == targetIP {
			return uint32(lineUID), uint32(lineInode), true, nil
		}

		if lineInode == 0 {
			continue
		}

		if !found || (bestUID == 0 && lineUID != 0) {
			bestUID = uint32(lineUID)
			bestInode = uint32(lineInode)
			found = true
		}
	}

	if found {
		return bestUID, bestInode, false, nil
	}
	return 0, 0, false, ErrNotFound
}

func parseHexAddrPort(s string, isV6 bool) (netip.Addr, uint16, error) {
	before, after, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("invalid addr:port: %s", s)
	}

	port64, err := strconv.ParseUint(after, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}

	var addr netip.Addr
	if isV6 {
		addr, err = parseHexIPv6(before)
	} else {
		addr, err = parseHexIPv4(before)
	}
	return addr, uint16(port64), err
}

func parseHexIPv4(s string) (netip.Addr, error) {
	if len(s) != 8 {
		return netip.Addr{}, fmt.Errorf("invalid ipv4 hex len: %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, err
	}
	var ip [4]byte
	if littleEndian {
		ip[0], ip[1], ip[2], ip[3] = b[3], b[2], b[1], b[0]
	} else {
		copy(ip[:], b)
	}
	return netip.AddrFrom4(ip), nil
}

func parseHexIPv6(s string) (netip.Addr, error) {
	if len(s) != 32 {
		return netip.Addr{}, fmt.Errorf("invalid ipv6 hex len: %d", len(s))
	}
	var ip [16]byte
	for i := range 4 {
		b, err := hex.DecodeString(s[i*8 : (i+1)*8])
		if err != nil {
			return netip.Addr{}, err
		}
		if littleEndian {
			ip[i*4+0] = b[3]
			ip[i*4+1] = b[2]
			ip[i*4+2] = b[1]
			ip[i*4+3] = b[0]
		} else {
			copy(ip[i*4:(i+1)*4], b)
		}
	}
	return netip.AddrFrom16(ip), nil
}

var littleEndian = func() bool {
	x := uint32(0x01020304)
	return *(*byte)(unsafe.Pointer(&x)) == 0x04
}()
