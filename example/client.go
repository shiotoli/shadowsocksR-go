package main

import (
	"time"

	"net"
	"log"
	"os"
	"net/url"
	"fmt"
	"io"
	"github.com/shiotoli/shadowsocksR-go"
	"errors"
	"strings"
	"strconv"
	"github.com/shiotoli/shadowsocksR-go/obfs"
	"github.com/shiotoli/shadowsocksR-go/ssr"
	"github.com/shiotoli/shadowsocksR-go/tools/socks"
	"github.com/shiotoli/shadowsocksR-go/protocol"
)

var (
	readTimeout = 600 * time.Second
)

// SSInfo fields that shadowsocks/shadowsocksr used only
type SSInfo struct {
	SSRInfo
	EncryptMethod   string
	EncryptPassword string
}

// SSRInfo fields that shadowsocksr used only
type SSRInfo struct {
	Obfs          string
	ObfsParam     string
	ObfsData      interface{}
	Protocol      string
	ProtocolParam string
	ProtocolData  interface{}
}

// BackendInfo all fields that a backend used
type BackendInfo struct {
	SSInfo
	Address string
	Type    string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	bi := &BackendInfo{
		Address: "hkt09.x.com:45672",
		Type:    "ssr",
		SSInfo: SSInfo{
			EncryptMethod:   "aes-128-ctr",
			EncryptPassword: "password",
			SSRInfo: SSRInfo{
				Protocol:      "auth_aes128_md5",
				ProtocolParam: "",
				Obfs:          "tls1.2_ticket_auth",
				ObfsParam:     "www.a.com",
			},
		},
	}

	bi.Listen("0.0.0.0:1088")
}

func (bi *BackendInfo) Listen(clientRawAddr string) {
	listener, err := net.Listen("tcp", clientRawAddr)
	if err != nil {
		//2019/01/09 20:03:54 ssr.go:55: listen tcp 127.0.0.1:43307: bind: address already in use
		log.Println(err)
		os.Exit(100) //fixme bind: address already in use
		return
	}
	for {
		localConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go bi.Handle(localConn)
	}
}

func (bi *BackendInfo) Handle(src net.Conn) {
	defer src.Close()
	//src.SetKeepAlive(true)
	src.(*net.TCPConn).SetKeepAlive(true)

	socks.ReadAddr(src)
	rawaddr, err := socks.Handshake(src)
	if err != nil {
		// UDP: keep the connection until disconnect then free the UDP socket
		if err == socks.Error(9) {
			buf := []byte{}
			// block here
			for {
				_, err := src.Read(buf)
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue
				}
				log.Println("UDP Associate End.")
				return
			}
		}
		log.Println("failed to get target address: %v", err)
		return
	}

	dst, err := bi.DialSSRConn(socks.Addr(rawaddr))
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		return //ignore i/o timeout
	}
	defer dst.Close()
	//dst.(*net.TCPConn).SetKeepAlive(true)

	_, _, err = tcpRelay(src, dst)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		log.Println("relay error: %v", err)
	}

	//go bi.Pipe(src, dst)
	//bi.Pipe(dst, src)
	//src.Close()
	//dst.Close()
}

func (bi *BackendInfo) DialSSRConn(rawaddr socks.Addr) (net.Conn, error) {
	u := &url.URL{
		Scheme: bi.Type,
		Host:   bi.Address,
	}
	v := u.Query()
	v.Set("encrypt-method", bi.EncryptMethod)
	v.Set("encrypt-key", bi.EncryptPassword)
	v.Set("obfs", bi.Obfs)
	v.Set("obfs-param", bi.ObfsParam)
	v.Set("protocol", bi.Protocol)
	v.Set("protocol-param", bi.ProtocolParam)
	u.RawQuery = v.Encode()

	ssrconn, err := NewSSRClient(u)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSR server failed :%v", err)
	}

	if bi.ObfsData == nil {
		bi.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(bi.ObfsData)

	if bi.ProtocolData == nil {
		bi.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(bi.ProtocolData)

	if _, err := ssrconn.Write(rawaddr); err != nil {
		ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}

// relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func tcpRelay(left, right net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}

func NewSSRClient(u *url.URL) (*shadowsocksr.SSTCPConn, error) {
	query := u.Query()
	encryptMethod := query.Get("encrypt-method")
	encryptKey := query.Get("encrypt-key")
	cipher, err := shadowsocksr.NewStreamCipher(encryptMethod, encryptKey)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{
		//Timeout:   time.Millisecond * 700,
		DualStack: true,
	}
	conn, err := dialer.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}

	conn.(*net.TCPConn).SetKeepAlive(true)

	ssconn := shadowsocksr.NewSSTCPConn(conn, cipher)
	if ssconn.Conn == nil || ssconn.RemoteAddr() == nil {
		return nil, errors.New("nil connection")
	}

	// should initialize obfs/protocol now
	rs := strings.Split(ssconn.RemoteAddr().String(), ":")
	port, _ := strconv.Atoi(rs[1])

	ssconn.IObfs = obfs.NewObfs(query.Get("obfs"))
	obfsServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  query.Get("obfs-param"),
	}
	ssconn.IObfs.SetServerInfo(obfsServerInfo)
	ssconn.IProtocol = protocol.NewProtocol(query.Get("protocol"))
	protocolServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  query.Get("protocol-param"),
	}
	ssconn.IProtocol.SetServerInfo(protocolServerInfo)

	return ssconn, nil
}
