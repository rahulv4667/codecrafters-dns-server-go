package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

type OpCode = uint8

const (
	OpCodeStandardQuery OpCode = 0
	OpCodeInverseQuery  OpCode = 1
	OpCodeServerRequest OpCode = 2
)

type ResponseCode = uint8

const (
	RespNoError        ResponseCode = 0
	RespFormatError    ResponseCode = 1
	RespServerFailure  ResponseCode = 2
	RespNameError      ResponseCode = 3
	RespNotImplemented ResponseCode = 4
	RespRefused        ResponseCode = 5
)

type dnsHeader struct {
	pktId                uint16
	isQueryIndicator     bool  // 1 for reply, 0 for question
	opCode               uint8 // specifies the kind of query
	isAuthoritativeAns   bool  // 1 if responding server 'owns' the domain queried
	truncated            bool  // 1 if msg is larger than 512 bytes
	isRecursionDesired   bool  // 1 if server should recursively resolve this
	isRecursionAvailable bool  // 1 to indicate that recursion is available
	reserved             uint8
	respCode             uint8  // response code indicating status of response
	qdCount              uint16 // question count
	anCount              uint16 // answer record count
	nsCount              uint16 // authority record count
	arCount              uint16 // additional record count
}

func (hdr *dnsHeader) String() string {
	return fmt.Sprintf("pkt_id:%v, isQuery:%v, opCode:%v, AuthoritativeAnswer:%v, truncated:%v, RecursionDesired:%v, RecursionAvailable:%v, ResponseCode:%v, Question Count:%v, Answer Count:%v, Authoritative Count:%v, Additional Record Count: %v", hdr.pktId, hdr.isQueryIndicator, hdr.opCode, hdr.isAuthoritativeAns, hdr.truncated, hdr.isRecursionDesired, hdr.isRecursionAvailable, hdr.respCode, hdr.qdCount, hdr.anCount, hdr.nsCount, hdr.arCount)
}

func (hdr *dnsHeader) decode(b []byte, read_offset int) (offset int, err error) {
	hdr.pktId = binary.BigEndian.Uint16(b[read_offset:read_offset+2])

	flags := binary.BigEndian.Uint16(b[read_offset+2:read_offset+4])
	hdr.isQueryIndicator = (flags & 0x8000) > 0
	hdr.opCode = uint8((flags & 0x7800) >> 11)
	hdr.isAuthoritativeAns = (flags & 0x0400) > 0
	hdr.truncated = (flags & 0x0200) > 0
	hdr.isRecursionDesired = (flags & 0x0100) > 0
	hdr.isRecursionAvailable = (flags & 0x0080) > 0
	hdr.reserved = uint8(flags & 0x0070)
	hdr.respCode = uint8(flags & 0x000F)

	hdr.qdCount = binary.BigEndian.Uint16(b[read_offset+4:read_offset+6])
	hdr.anCount = binary.BigEndian.Uint16(b[read_offset+6:read_offset+8])
	hdr.nsCount = binary.BigEndian.Uint16(b[read_offset+8:read_offset+10])
	hdr.arCount = binary.BigEndian.Uint16(b[read_offset+10:read_offset+12])
	return read_offset+12, nil
}

func (hdr *dnsHeader) encode(b []byte) (res_b []byte, err error) {
	b = binary.BigEndian.AppendUint16(b, hdr.pktId)
	var flags uint16 = 0
	if hdr.isQueryIndicator {
		flags |= 0x8000
	}
	if hdr.opCode > 0 {
		flags |= (uint16(hdr.opCode) << 11)
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

type RRType = uint16

const (
	A     RRType = 1  // host address
	NS    RRType = 2  // authoritative name server
	MD    RRType = 3  // mail destination (obsolete - use MX)
	MF    RRType = 4  // mail forwarder (obsolete - use MX)
	CNAME RRType = 5  // canonical name for an alias
	SOA   RRType = 6  // start of a zone of authority
	MB    RRType = 7  // mailbox domain name (EXPERIMENTAL)
	MG    RRType = 8  // mail group member (EXPERIMENTAL)
	MR    RRType = 9  // mail rename domain name (EXPERIMENTAL)
	NULL  RRType = 10 // null RR (EXPERIMENTAL)
	WKS   RRType = 11 // well known service description
	PTR   RRType = 12 // domain name pointer
	HINFO RRType = 13 // host information
	MINFO RRType = 14 // mailbox or mail list information
	MX    RRType = 15 // mail exchange
	TXT   RRType = 16 // text strings
)

type ClassType = uint16

const (
	IN ClassType = 1 // Internet
	CS ClassType = 2 // CSNET (obsolete)
	CH ClassType = 3 // chaos class
	HS ClassType = 4 // Hesiod
)

type dnsQuestion struct {
	name      string
	rrType    RRType
	classCode ClassType
}

func (dnsQs *dnsQuestion) String() string {
	return fmt.Sprintf("name=%v,rrtype=%v,classCode=%v", dnsQs.name, dnsQs.rrType, dnsQs.classCode)
}

func (dnsQs *dnsQuestion) decode_name(b []byte, read_offset int) (offset int, err error) {
	for b[read_offset] != 0 {
		if b[read_offset] & 0xC0 > 0 { // is a pointer
			pointingOffset := binary.BigEndian.Uint16(b[read_offset:read_offset+2])
			pointingOffset &= 0x3FFF
			var finalOffset int  =0
			finalOffset, err = dnsQs.decode_name(b, int(pointingOffset))
			if b[finalOffset-1] != 0 {
				return finalOffset, fmt.Errorf("Error while decoding name from pointer")
			} else if err != nil {
				return finalOffset, err
			}
			read_offset += 2
			return read_offset, err
		} else {
			var name_len int = int(b[read_offset])
			fmt.Printf("Question off:%v name_len:%v \n", read_offset, name_len)
			dnsQs.name += string(b[read_offset+1 : read_offset+name_len+1])
			dnsQs.name += "."
			read_offset = read_offset + name_len + 1
		}
	}
	// remove last dot
	// name_len := len(dnsQs.name) - 1
	dnsQs.name = dnsQs.name[:len(dnsQs.name)-1]
	fmt.Printf("Question name=%v\n", dnsQs.name)
	read_offset += 1
	return read_offset, nil
}

func (dnsQs *dnsQuestion) decode(b []byte, read_offset int) (offset int, err error) {
	read_offset, err = dnsQs.decode_name(b, read_offset)
	if err != nil {
		fmt.Println("err while decoding name. err=", err)
		return read_offset, err
	}
	dnsQs.rrType = binary.BigEndian.Uint16(b[read_offset : read_offset+2])
	read_offset += 2
	dnsQs.classCode = binary.BigEndian.Uint16(b[read_offset : read_offset+2])
	read_offset += 2
	return read_offset, nil
}

func (dnsQs *dnsQuestion) encode(b []byte) (res_b []byte, err error) {
	domainNames := strings.Split(dnsQs.name, ".")
	for _, domainName := range domainNames {
		b = append(b, uint8(len(domainName)))
		b = append(b, domainName...)
	}
	b = append(b, byte(0))
	b = binary.BigEndian.AppendUint16(b, dnsQs.rrType)
	b = binary.BigEndian.AppendUint16(b, dnsQs.classCode)
	return b, nil
}

type dnsResourceRecord struct {
	name      string
	rrType    RRType    // type of RR
	classCode ClassType // class code
	ttl       uint32    // time to live
	rdLen     uint16    // RDATA length field
	rdata     []byte    // RDATA
}

func (dnsRR *dnsResourceRecord) Clone() dnsResourceRecord {
	dnsRRClone := *dnsRR
	dnsRRClone.rdata = make([]byte, dnsRR.rdLen)
	copy(dnsRRClone.rdata, dnsRR.rdata)
	return dnsRRClone
}

func (dnsRR *dnsResourceRecord) String() string {
	return fmt.Sprintf("name=%v,rrType=%v,classCode=%v,ttl=%v,rdLen=%v,rdata=%v", dnsRR.name, dnsRR.rrType, dnsRR.classCode, dnsRR.ttl, dnsRR.rdLen, dnsRR.rdata)
}

func (dnsRR *dnsResourceRecord) decode_name(b []byte, read_offset int) (offset int, err error) {
	for b[read_offset] != 0 {
		if b[read_offset] & 0xC0 > 0 { // is a pointer
			pointingOffset := binary.BigEndian.Uint16(b[read_offset:read_offset+2])
			pointingOffset &= 0x3FFF
			var finalOffset int  =0
			finalOffset, err = dnsRR.decode_name(b, int(pointingOffset))
			if b[finalOffset-1] != 0 {
				return finalOffset, fmt.Errorf("Error while decoding name from pointer")
			} else if err != nil {
				return finalOffset, err
			}
			read_offset += 2
			return read_offset, err
		} else {
			var name_len int = int(b[read_offset])
			fmt.Printf("RR off:%v name_len:%v \n", read_offset, name_len)
			dnsRR.name += string(b[read_offset+1 : read_offset+name_len+1])
			dnsRR.name += "."
			read_offset = read_offset + name_len + 1
		}
	}
	// remove last dot
	// name_len := len(dnsQs.name) - 1
	dnsRR.name = dnsRR.name[:len(dnsRR.name)-1]
	fmt.Printf("RR name=%v\n", dnsRR.name)
	read_offset += 1
	return read_offset, nil
}

func (dnsRR *dnsResourceRecord) decode(b []byte, read_offset int) (offset int, err error) {
	read_offset, err = dnsRR.decode_name(b, read_offset)
	if err != nil {
		fmt.Println("err while decoding name. err=", err)
		return read_offset, err
	}
	dnsRR.rrType = binary.BigEndian.Uint16(b[read_offset : read_offset+2])
	read_offset += 2
	dnsRR.classCode = binary.BigEndian.Uint16(b[read_offset : read_offset+2])
	read_offset += 2
	dnsRR.ttl = binary.BigEndian.Uint32(b[read_offset: read_offset+4])
	read_offset += 4
	dnsRR.rdLen = binary.BigEndian.Uint16(b[read_offset: read_offset+2])
	read_offset += 2
	dnsRR.rdata = []byte{}
	dnsRR.rdata = append(dnsRR.rdata, b[read_offset:read_offset+int(dnsRR.rdLen)]...)
	read_offset+=int(dnsRR.rdLen)
	return read_offset, nil
}


func (dnsRR *dnsResourceRecord) encode(b []byte) (res_b []byte, err error) {
	domainNames := strings.Split(dnsRR.name, ".")
	for _, domainName := range domainNames {
		b = append(b, uint8(len(domainName)))
		b = append(b, domainName...)
	}
	b = append(b, byte(0))
	b = binary.BigEndian.AppendUint16(b, dnsRR.rrType)
	b = binary.BigEndian.AppendUint16(b, dnsRR.classCode)
	b = binary.BigEndian.AppendUint32(b, dnsRR.ttl)
	b = binary.BigEndian.AppendUint16(b, dnsRR.rdLen)
	b = append(b, dnsRR.rdata...)
	return b, nil
}

type dnsMessage struct {
	hdr             dnsHeader
	questions       []dnsQuestion
	resourceRecords []dnsResourceRecord
}

func (dnsMsg *dnsMessage) Clone() dnsMessage {
	dnsMsgClone := *dnsMsg
	dnsMsgClone.questions = make([]dnsQuestion, 0)
	dnsMsgClone.questions = append(dnsMsgClone.questions, dnsMsg.questions...)

	dnsMsgClone.resourceRecords = make([]dnsResourceRecord, 0)
	for _, rr := range dnsMsg.resourceRecords {
		dnsMsgClone.resourceRecords = append(dnsMsgClone.resourceRecords, rr.Clone())
	}
	return dnsMsgClone
}

func (dnsMsg *dnsMessage) String() string {
	var res string
	res += "{\n"
	res += dnsMsg.hdr.String()
	res += "\nQuestions["
	for _, qs := range dnsMsg.questions {
		res += ("\t"+qs.String()+"\n")
	}
	res += "\n]\nResourceRecords[\n"
	for _, rr := range dnsMsg.resourceRecords {
		res += ("\t"+rr.String()+"\n")
	}
	res += "\n]"
	res += "\n}"
	return res
}

func (dnsMsg *dnsMessage) decode(b []byte, read_offset int) (offset int, err error) {
	read_offset, err = dnsMsg.hdr.decode(b, read_offset)
	if err != nil {
		fmt.Println("error while decoding header=", err)
		return read_offset, err
	}

	for questionCnt:=0; questionCnt<int(dnsMsg.hdr.qdCount); questionCnt++ {
		dnsQues := dnsQuestion{}
		read_offset, err = dnsQues.decode(b, read_offset)
		if err != nil {
			fmt.Printf("error while decoding question #%v. err=%v", questionCnt+1, err)
			return read_offset, err
		}
		dnsMsg.questions = append(dnsMsg.questions, dnsQues)
	}

	for answerCnt :=0; answerCnt<int(dnsMsg.hdr.anCount); answerCnt++ {
		dnsRR := dnsResourceRecord{}
		read_offset, err = dnsRR.decode(b, read_offset)
		if err != nil {
			fmt.Printf("error while decoding resource record #%v. err=%v", answerCnt+1, err)
			return read_offset, err
		}
		dnsMsg.resourceRecords = append(dnsMsg.resourceRecords, dnsRR)
	}

	return read_offset, nil
}



func (dnsMsg *dnsMessage) encode(b []byte) (res_b []byte, err error) {
	b, err = dnsMsg.hdr.encode(b)
	if err != nil {
		return b, err
	}

	for _, dnsQs := range dnsMsg.questions {
		b, err = dnsQs.encode(b)
		if err != nil {
			return b, err
		}
	}

	for _, dnsRR := range dnsMsg.resourceRecords {
		b, err = dnsRR.encode(b)
		if err != nil {
			return b, err
		}
	}

	return b, nil
}

func forwardQuery(dnsMsgReq* dnsMessage, resolver *string) (dnsMsgResp dnsMessage, err error) {
	dnsMsgResp = dnsMsgReq.Clone()

	// encode req
	b, err := dnsMsgReq.encode([]byte{})
	if err != nil {
		fmt.Println("Error while forwarding request:", err)
		return dnsMsgResp, err
	}
	reqSize := len(b)

	udpConn, err := net.Dial("udp", *resolver)
	if err != nil {
		fmt.Println("Error while connecting to resolver: ", err)
		return dnsMsgResp, err
	}

	// write request
	num_written := 0
	for num_written < reqSize {
		n, err := udpConn.Write(b[num_written:])
		if err != nil {
			fmt.Println("Error while writing request to resolver: ", err)
			return dnsMsgResp, err
		}
		num_written += n
	}
	fmt.Printf("num_written:%v, reqSize: %v\n", num_written, reqSize)

	// read response
	response := make([]byte, 1024)
	n, err := udpConn.Read(response)
	if err != nil {
		fmt.Println("Error while reading response from resolver: ", err)
		return dnsMsgResp, err
	}
	offset, err := dnsMsgResp.decode(response, 0)
	if err != nil {
		fmt.Println("Error decoding message: err=", err)
		return dnsMsgResp, err
	}
	if offset != n {
		var errStr string
		if err != nil {
			errStr = err.Error()
		}
		err = fmt.Errorf("error while decoding response. err=%v read_offset=%v, msg_size=%v", errStr, offset, n)
		return dnsMsgResp, err
	}
	fmt.Println("read_offset=", offset, ", n=", n)
	return dnsMsgResp, nil
}

func respond(dnsMsgReq* dnsMessage, resolver *string) (dnsMsgResp dnsMessage, err error) {
	dnsMsgResp = dnsMsgReq.Clone()
	fmt.Println("Received Request:", dnsMsgReq.String())

	for qCnt:=0; qCnt<int(dnsMsgReq.hdr.qdCount); qCnt++ {
		// fill new req
		dnsMsgForwardingReq := dnsMessage{}
		dnsMsgForwardingReq.hdr = dnsMsgReq.hdr
		dnsMsgForwardingReq.hdr.pktId = dnsMsgReq.hdr.pktId + uint16(qCnt) + 1
		dnsMsgForwardingReq.hdr.qdCount = 1
		dnsMsgForwardingReq.questions = append(dnsMsgForwardingReq.questions, dnsMsgReq.questions[qCnt])

		dnsResolverResp, err := forwardQuery(&dnsMsgForwardingReq, resolver)
		if err != nil {
			fmt.Printf("Error resolving query #%v, err=%v\n", qCnt, err)
			return dnsMsgResp, err
		}

		fmt.Printf("Forwarding Req: %v\n", dnsMsgForwardingReq.String())
		fmt.Printf("Resolved resp: %v\n", dnsResolverResp.String())
		// append new resp
		if dnsResolverResp.hdr.opCode != OpCodeStandardQuery || dnsResolverResp.hdr.respCode != RespNoError {
			fmt.Println("Error in resolution. Copying header")
			dnsMsgResp.hdr = dnsResolverResp.hdr
			dnsMsgResp.hdr.pktId = dnsMsgReq.hdr.pktId
			break
		}

		dnsMsgResp.hdr.anCount++
		dnsMsgResp.resourceRecords = append(dnsMsgResp.resourceRecords, dnsResolverResp.resourceRecords[0].Clone())
	}

	dnsMsgResp.hdr.isQueryIndicator = true

	return dnsMsgResp, nil
}
func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	var resolver = flag.String("resolver", "", "DNS address in format <ip>:<port>")
	flag.Parse()
	fmt.Println("resolver=", *resolver)

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

		dnsMsg := dnsMessage{}
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		var offset int
		offset, err = dnsMsg.decode([]byte(receivedData), 0)
		fmt.Printf("decoded msg. offset=%v err=%v\n", offset, err)
		dnsMsgResp, err := respond(&dnsMsg, resolver)

		response := []byte{}
		response, err = dnsMsgResp.encode(response)
		if err != nil {
			fmt.Println("Error encoding dns message: ", err)
			os.Exit(0)
		}
		fmt.Printf("Resource=%v\n", hex.EncodeToString(response))

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
