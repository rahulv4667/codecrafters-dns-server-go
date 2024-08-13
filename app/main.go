package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

type OpCode = uint8

const (
	OpCodeStandardQuery OpCode = 0
	OpCodeInverseQuery OpCode = 1
	OpCodeServerRequest OpCode = 2
)

type ResponseCode = uint8

const (
	RespNoError ResponseCode = 0
	RespFormatError ResponseCode = 1
	RespServerFailure ResponseCode = 2
	RespNameError ResponseCode = 3
	RespNotImplemented ResponseCode = 4
	RespRefused ResponseCode = 5
)

type dnsHeader struct {
	pktId uint16
	isQueryIndicator bool // 1 for reply, 0 for question
	opCode uint8 // specifies the kind of query
	isAuthoritativeAns bool // 1 if responding server 'owns' the domain queried
	truncated bool // 1 if msg is larger than 512 bytes
	isRecursionDesired bool // 1 if server should recursively resolve this
	isRecursionAvailable bool // 1 to indicate that recursion is available
	reserved uint8
	respCode uint8 // response code indicating status of response
	qdCount uint16 // question count
	anCount uint16 // answer record count
	nsCount uint16 // authority record count
	arCount uint16 // additional record count
}

func (hdr *dnsHeader) String() string {
	return fmt.Sprintf("pkt_id:%v, isQuery:%v, opCode:%v, AuthoritativeAnswer:%v, truncated:%v, RecursionDesired:%v, RecursionAvailable:%v, ResponseCode:%v, Question Count:%v, Answer Count:%v, Authoritative Count:%v, Additional Record Count: %v", hdr.pktId, hdr.isQueryIndicator, hdr.opCode, hdr.isAuthoritativeAns, hdr.truncated, hdr.isRecursionDesired, hdr.isRecursionAvailable, hdr.respCode, hdr.qdCount, hdr.anCount, hdr.nsCount, hdr.arCount)
}

func (hdr* dnsHeader) decode(b []byte) {
	binary.BigEndian.PutUint16(b[0:2], hdr.pktId)

	var flags uint16
	binary.BigEndian.PutUint16(b[2:4], flags)
	// parse flags
	hdr.isQueryIndicator = (flags & 0x8000) > 0
	hdr.opCode = uint8((flags & 0x7800) - 0x7FF)
	hdr.isAuthoritativeAns = (flags & 0x0400) > 0
	hdr.truncated = (flags & 0x0200) > 0
	hdr.isRecursionDesired = (flags & 0x0100) > 0
	hdr.isRecursionAvailable = (flags & 0x0080) > 0
	hdr.reserved = uint8(flags & 0x0070)
	hdr.respCode = uint8(flags & 0x000F)

	binary.BigEndian.PutUint16(b[4:6], hdr.qdCount)
	binary.BigEndian.PutUint16(b[6:8], hdr.anCount)
	binary.BigEndian.PutUint16(b[8:10], hdr.nsCount)
	binary.BigEndian.PutUint16(b[10:12], hdr.arCount)
}

func (hdr* dnsHeader) encode(b []byte) (res_b []byte, err error) {
	b = binary.BigEndian.AppendUint16(b, hdr.pktId)
	var flags uint16 = 0
	if hdr.isQueryIndicator {
		flags |= 0x8000
	}
	if hdr.opCode > 0 {
		flags |= (uint16(hdr.opCode) + 0x7ff)
	}
	if hdr.isAuthoritativeAns {
		flags |= 0x0400
	}
	if hdr.truncated {
		flags |= 0x0200
	}
	if hdr.isRecursionDesired {
		flags |= 0x0100
	}
	if hdr.isRecursionAvailable {
		flags |= 0x0080
	}
	if hdr.reserved > 0 {
		flags |= uint16(hdr.reserved)
	}
	if hdr.respCode > 0 {
		flags |= uint16(hdr.respCode)
	}
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, hdr.qdCount)
	b = binary.BigEndian.AppendUint16(b, hdr.anCount)
	b = binary.BigEndian.AppendUint16(b, hdr.nsCount)
	b = binary.BigEndian.AppendUint16(b, hdr.arCount)
	return b, nil
}

type dnsQuestion struct {
	name string
	rrType uint16
	classCode uint16
}

type dnsResourceRecord struct {
	nameLen uint8
	name string
	rrType uint16 		// type of RR
	classCode uint16	// class code
	ttl uint32			// time to live
	rdLen uint16		// RDATA length field
	rdata []byte		// RDATA
}

type dnsMessage struct {
	hdr dnsHeader
	question []dnsQuestion
	resourceRecord []dnsResourceRecord
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage
	//
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		response := []byte{}
		respHeader := dnsHeader{}
		respHeader.pktId = 1234
		respHeader.isQueryIndicator=true
		respHeader.opCode = 0
		respHeader.isAuthoritativeAns = false
		respHeader.truncated = false
		respHeader.isRecursionDesired = false
		respHeader.isRecursionAvailable = false
		respHeader.reserved = 0
		respHeader.respCode = 0
		respHeader.qdCount = 0
		respHeader.anCount = 0
		respHeader.nsCount = 0
		respHeader.arCount = 0
		fmt.Println("Enconding packet header=", respHeader.String())
		response, err = respHeader.encode(response)
		fmt.Println("Resp bytes=", len(response))
		if err!=nil {
			fmt.Println("Error while encoding response header:", err)
			os.Exit(0)
		}


		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
