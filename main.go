package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/xbreezes/go-socks5/utils"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	socksVer5       = 0x05
	socksCmdConnect = 0x01
)

var (
	Commands = []string{"CONNECT", "BIND", "UDP ASSOCIATE"}
	AddrType = []string{"", "IPv4", "", "Domain", "IPv6"}
	Conns    = make([]net.Conn, 0)

	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support noauth method")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks only support connect command")
)

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	buf := make([]byte, 258)

	var n int

	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	//验证 Socks 版本
	if buf[idVer] != socksVer5 {
		return errVer
	}
	nmethod := int(buf[idNmethod]) //客户端支持的认证模式数量
	msgLen := nmethod + 2          //认证数据长度
	if n == msgLen {               // handshake done, common case //已读取完所有认证数据
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case //读取剩余的所有认证数据
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	/*
				  X'00' NO AUTHENTICATION REQUIRED
		          X'01' GSSAPI
		          X'02' USERNAME/PASSWORD
		          X'03' to X'7F' IANA ASSIGNED
		          X'80' to X'FE' RESERVED FOR PRIVATE METHODS
		          X'FF' NO ACCEPTABLE METHODS
	*/
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func parseTarget(conn net.Conn) (host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int

	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	/*
		CONNECT X'01'
		BIND X'02'
		UDP ASSOCIATE X'03'
	*/
	//判断连接模式
	if buf[idCmd] > 0x03 || buf[idCmd] == 0x00 {
		log.Println("未知 Command", buf[idCmd])
	}
	log.Println("Command:", Commands[buf[idCmd]-1])
	if buf[idCmd] != socksCmdConnect { //仅支持CONNECT模式
		err = errCmd
		return
	}

	//读取代理目标地址
	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm: //域名
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen { //已读取所有目标地址信息
		// common case, do nothing
	} else if n < reqLen { // rare case // 读取剩余的目标地址信息
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	//转化目标地址为可阅读模式
	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

func pipeWhenClose(conn net.Conn, target string) {

	log.Println("Connect remote ", target, "...")
	remoteConn, err := net.DialTimeout("tcp", target, time.Duration(time.Second*15))
	if err != nil {
		log.Println("Connect remote :", err)
		return
	}

	tcpAddr := remoteConn.LocalAddr().(*net.TCPAddr)
	if tcpAddr.Zone == "" {
		if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
			tcpAddr.Zone = "ip4"
		} else {
			tcpAddr.Zone = "ip6"
		}
	}

	log.Println("Connect remote success @", tcpAddr.String())

	rep := make([]byte, 256)
	rep[0] = 0x05
	rep[1] = 0x00 // success
	rep[2] = 0x00 //RSV

	//IP
	if tcpAddr.Zone == "ip6" {
		rep[3] = 0x04 //IPv6
	} else {
		rep[3] = 0x01 //IPv4
	}

	var ip net.IP
	if "ip6" == tcpAddr.Zone {
		ip = tcpAddr.IP.To16()
	} else {
		ip = tcpAddr.IP.To4()
	}
	pindex := 4
	for _, b := range ip {
		rep[pindex] = b
		pindex += 1
	}
	rep[pindex] = byte((tcpAddr.Port >> 8) & 0xff)
	rep[pindex+1] = byte(tcpAddr.Port & 0xff)
	conn.Write(rep[0 : pindex+2])
	//传输数据

	defer remoteConn.Close()
	//Copy本地到远程
	go utils.Copy(conn, remoteConn)
	//Copy远程到本地
	utils.Copy(remoteConn, conn)
}

func handleConnection(conn net.Conn) {
	Conns = append(Conns, conn)
	defer func() {
		for i, c := range Conns {
			if c == conn {
				Conns = append(Conns[:i], Conns[i+1:]...)
			}
		}
		conn.Close()
	}()
	if err := handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	addr, err := parseTarget(conn)
	if err != nil {
		log.Println("socks consult transfer mode or parse target :", err)
		return
	}
	pipeWhenClose(conn, addr)
}

func main() {
	ln, err := net.Listen("tcp", ":40000")
	if err != nil {
		panic(err)
		return
	}
	go func() {
		lastC := len(Conns)
		log.Println("alive connections:", lastC)
		for _ = range time.Tick(time.Second) {
			tc := len(Conns)
			if tc != lastC {
				log.Println("alive connections:", tc)
				lastC = tc
			}
		}
	}()
	log.Println("Start @", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		log.Println("new client:", conn.RemoteAddr())
		go handleConnection(conn)
	}
}
