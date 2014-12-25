package main

import (
	"fmt"
	"net"
	"time"
)

var (
	Commands = []string{"CONNECT", "BIND", "UDP ASSOCIATE"}
	AddrType = []string{"", "IPv4", "", "Domain", "IPv6"}
	Conns    = make([]net.Conn, 0)
)

func handleSocks4(conn net.Conn, buf []byte) {
	rep := make([]byte, 512)
	rep[0] = 0x05
	rep[1] = 0xFF //协议不兼容
	conn.Write(rep[0:2])
}

func handleSocks5(conn net.Conn, buf []byte) {
	rep := make([]byte, 512)

	fmt.Println("Method Count:", buf[1])
	fmt.Print("Methods:")

	supportNP := false

	for _, m := range buf[2 : 2+buf[1]] {
		if m == 0x02 {
			supportNP = true
		}
		fmt.Printf("%x,", m)
	}
	fmt.Println()

	if !supportNP {
		rep[0] = 0x05
		rep[1] = 0xFF //协议不兼容
		conn.Write(rep[0:2])
		return
	}
	//协商认证模式
	rep[0] = 0x05
	rep[1] = 0x02 // 用户名/密码
	conn.Write(rep[0:2])

	//获取认证信息
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}

	uname := string(buf[2 : 2+buf[1]])
	upwd := string(buf[3+buf[1] : 3+buf[1]+buf[3+buf[1]]])

	fmt.Println("UNAME:", uname)
	fmt.Println("PASSWD:", upwd)

	//反馈验证结果
	rep[0] = 0x00
	rep[1] = 0x00 // 成功
	conn.Write(rep[0:2])

	//协商连接
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	if buf[1] > 0x03 || buf[1] == 0x00 {
		fmt.Println("Unknown command")
		return
	}

	fmt.Println("Command:", Commands[buf[1]-1])

	// 如果不是TCP Stream 则提示Command 不受支持
	if buf[1] != 0x01 {
		rep[0] = 0x05
		rep[1] = 0x07
		conn.Write(rep[0:3])
		return
	}

	if buf[3] > 0x04 || buf[3] == 0x02 || buf[3] == 0x00 {
		fmt.Println("Unknown address type")
		return
	}

	fmt.Println("AddType:", AddrType[buf[3]], buf[3])
	pindex := 0
	rAddr := net.TCPAddr{}
	rdomain := ""
	switch int(buf[3]) {
	case 0x01:
		pindex = 8
		rAddr.IP = buf[4:8]
		rAddr.Zone = "ip4"
		break
	case 0x03:
		pindex = 5 + int(buf[4])
		rdomain = string(buf[5 : 5+buf[4]])
		break
	case 0x04:
		pindex = 20
		rAddr.IP = buf[4:20]
		rAddr.Zone = "ip6"
		break
	}
	rport := int(buf[pindex])<<8 | int(buf[pindex+1])
	if rport == 0 {
		rport = 80
	}
	var remote string
	if rdomain != "" { // domain
		fmt.Println("Domain:", rdomain)
		nip, err := net.LookupIP(rdomain)
		if err != nil {
			fmt.Println(err)
			rep[0] = 0x05
			rep[1] = 0x03 //网络不通
			conn.Write(rep[0:2])
			return
		}
		if len(nip) < 0 {
			rep[0] = 0x05
			rep[1] = 0x04 //域名不能解析
			conn.Write(rep[0:2])
			fmt.Println("Cannt loopip for domain:", rdomain)
		}
		fmt.Println("NSLookup:")
		for _, i := range nip {
			mip, _ := net.IP(i).MarshalText()
			fmt.Println(string(mip))
		}
		rAddr.IP = nip[0]
		if rAddr.IP.Equal(rAddr.IP.To4()) {
			rAddr.Zone = "ip4"
		} else {
			rAddr.Zone = "ip6"
		}
	}

	var rAddrIp []byte
	if "ip6" == rAddr.Zone {
		fmt.Println("ipv6")
		rAddrIp, _ = rAddr.IP.MarshalText()
		remote = fmt.Sprintf("[%s]:%d", string(rAddrIp), rport)
	} else {
		fmt.Println("ipv4")
		rAddrIp, _ = rAddr.IP.To4().MarshalText()
		remote = fmt.Sprintf("%s:%d", string(rAddrIp), rport)
	}

	fmt.Println("Selected Remote:", remote)
	fmt.Println("Connect remote...")
	rcon, err := net.DialTimeout("tcp", remote, time.Duration(time.Second*15))
	if err != nil {
		fmt.Println(err)
		rep[0] = 0x05
		rep[1] = 0x04
		conn.Write(rep[0:2])
		return
	}

	defer rcon.Close()

	tcpAddr := rcon.LocalAddr().(*net.TCPAddr)
	if tcpAddr.Zone == "" {
		if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
			tcpAddr.Zone = "ip4"
		} else {
			tcpAddr.Zone = "ip6"
		}
	}

	fmt.Println("Local IP Zone:", tcpAddr.Zone)
	fmt.Println("Connect remote success @", tcpAddr.String())

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
	tip, _ := ip.MarshalText()
	fmt.Println(string(tip))
	pindex = 4
	for i, b := range ip {
		rep[4+i] = b
		pindex += 1
	}
	rep[pindex] = byte((tcpAddr.Port >> 8) & 0xff)
	rep[pindex+1] = byte(tcpAddr.Port & 0xff)

	bindLocal := fmt.Sprintf("%s:%d", tip, int(rep[pindex])<<8|int(rep[pindex+1]))
	fmt.Println("Bind:", bindLocal)
	conn.Write(rep[0 : pindex+3])
	//传输数据

	//Copy本地到远程
	go func() {
		inBuf := make([]byte, 40960)
		for {
			c, err := conn.Read(inBuf)
			if err != nil {
				rcon.Close()
				fmt.Println("C:", err)
				break
			}
			if c > 0 {
				rcon.Write(inBuf[0:c])
			}
		}
	}()
	//Copy本地到远程
	outBuf := make([]byte, 40960)
	for {
		c, err := rcon.Read(outBuf)
		if err != nil {
			conn.Close()
			fmt.Println("S:", err)
			break
		}
		if c > 0 {
			conn.Write(outBuf[0:c])
		}
	}
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
	buf := make([]byte, 512)
	rep := make([]byte, 2)

	c, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	//验证Socks版本
	fmt.Println("C:", c)
	fmt.Println("Socks Version:", buf[0])
	switch buf[0] {
	case 0x05:
		handleSocks5(conn, buf)
	case 0x04:
		handleSocks4(conn, buf)
	default:
		rep[0] = 0x05
		rep[1] = 0xFF //
		conn.Write(rep[0:2])
	}
}

func main() {
	ln, err := net.Listen("tcp", ":7074")
	if err != nil {
		fmt.Println(err)
		return
	}
	go func() {
		lastC := len(Conns)
		fmt.Println("Alive Connections:", lastC)
		for _ = range time.Tick(time.Second) {
			tc := len(Conns)
			if tc != lastC {
				fmt.Println("Alive Connections:", tc)
				lastC = tc
			}
		}
	}()
	fmt.Println("Start @", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("new client:", conn.RemoteAddr())
		go handleConnection(conn)
	}
}
