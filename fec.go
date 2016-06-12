package kcp

import "encoding/binary"

const (
	fecHeaderSize      = 6
	fecHeaderSizePlus2 = fecHeaderSize + 2 // plus 2B data size
	fecOverflow        = 1e7
	typeData           = 0xf1
	typeFEC            = 0xf2
)

type (
	// FEC defines forward error correction for packets
	FEC struct {
		rx      []fecPacket // ordered rx queue
		rxlimit int         // queue size limit
		cluster int         // fec cluster size
		next    uint32      // next seqid
	}

	fecPacket struct {
		seqid uint32
		flag  uint16
		data  []byte
	}
)

func newFEC(cluster, rxlimit int) *FEC {
	if cluster < 1 || rxlimit < cluster {
		return nil
	}

	fec := new(FEC)
	fec.cluster = cluster
	fec.rxlimit = rxlimit
	return fec
}

// decode a fec packet
func fecDecode(data []byte) fecPacket {
	var pkt fecPacket
	buf := make([]byte, len(data))
	copy(buf, data)

	pkt.seqid = binary.LittleEndian.Uint32(buf)
	pkt.flag = binary.LittleEndian.Uint16(buf[4:])
	pkt.data = buf[6:]
	return pkt
}

func (fec *FEC) markData(data []byte) {
	binary.LittleEndian.PutUint32(data, fec.next)
	binary.LittleEndian.PutUint16(data[4:], typeData)
	fec.next++
}

func (fec *FEC) markFEC(data []byte) {
	binary.LittleEndian.PutUint32(data, fec.next)
	binary.LittleEndian.PutUint16(data[4:], typeFEC)
	fec.next++
}

// input a fec packet
func (fec *FEC) input(pkt fecPacket) []byte {
	n := len(fec.rx) - 1
	insert_idx := 0
	for i := n; i >= 0; i-- {
		if pkt.seqid == fec.rx[i].seqid { // de-duplicate
			return nil
		} else if pkt.seqid > fec.rx[i].seqid { // insertion
			insert_idx = i + 1
			break
		}
	}

	// insert into ordered rx queue
	if insert_idx == n+1 {
		fec.rx = append(fec.rx, pkt)
	} else {
		fec.rx = append(fec.rx, fecPacket{})
		copy(fec.rx[insert_idx+1:], fec.rx[insert_idx:])
		fec.rx[insert_idx] = pkt
	}

	var recovered []byte
	for i := insert_idx; i <= insert_idx+fec.cluster && i < len(fec.rx); i++ {
		if fec.rx[i].flag == typeFEC {
			ecc := &fec.rx[i]
			first := i - fec.cluster
			if first >= 0 && fec.rx[first].seqid == ecc.seqid-uint32(fec.cluster) {
				// normal flow, eg: [1,2,3,[4]]
				copy(fec.rx[first:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.cluster-1]
				break
			} else if first+1 >= 0 && (fec.rx[first+1].seqid == ecc.seqid-uint32(fec.cluster) ||
				fec.rx[first+1].seqid == ecc.seqid-uint32(fec.cluster)+1) {
				// recoverable data, eg: [2,3,[4]], [1,3,[4]], [1,2,[4]]
				recovered = ecc.data
				for j := first + 1; j < i; j++ {
					xorBytes(recovered, recovered, fec.rx[j].data)
				}
				copy(fec.rx[first+1:], fec.rx[i+1:])
				fec.rx = fec.rx[:len(fec.rx)-fec.cluster]
				break
			} else {
				break
			}
		}
	}

	// prevention of seqid overflows uint32
	if len(fec.rx) >= 2 {
		n := len(fec.rx) - 1
		if int64(fec.rx[n].seqid)-int64(fec.rx[0].seqid) > fecOverflow {
			fec.rx = nil
		}
	}

	// keep rxlen
	if len(fec.rx) > fec.rxlimit {
		fec.rx = fec.rx[1:]
	}
	return recovered
}

func (fec *FEC) calcECC(data [][]byte) []byte {
	if len(data) != fec.cluster {
		return nil
	}

	ecc := data[0]
	ecc_idx := 0
	for i := 1; i < len(data); i++ {
		if len(ecc) < len(data[i]) {
			ecc = data[i]
			ecc_idx = i
		}
	}

	for i := 0; i < len(data); i++ {
		if i != ecc_idx {
			xorBytes(ecc, ecc, data[i])
		}
	}
	return ecc
}
