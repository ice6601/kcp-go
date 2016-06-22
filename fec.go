package kcp

import (
	"encoding/binary"
	"log"

	"github.com/klauspost/reedsolomon"
)

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
		rx           []fecPacket // ordered rx queue
		rxlimit      int         // queue size limit
		dataShards   int
		parityShards int
		shardSize    int
		next         uint32 // next seqid
		enc          reedsolomon.Encoder
	}

	fecPacket struct {
		seqid uint32
		flag  uint16
		data  []byte
	}
)

func newFEC(rxlimit, dataShards, parityShards int) *FEC {
	if rxlimit < dataShards+parityShards {
		return nil
	}

	fec := new(FEC)
	fec.rxlimit = rxlimit
	fec.dataShards = dataShards
	fec.parityShards = parityShards
	fec.shardSize = dataShards + parityShards
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		log.Println(err)
		return nil
	}
	fec.enc = enc
	return fec
}

// decode a fec packet
func fecDecode(data []byte) fecPacket {
	var pkt fecPacket
	pkt.seqid = binary.LittleEndian.Uint32(data)
	pkt.flag = binary.LittleEndian.Uint16(data[4:])
	pkt.data = data[6:]
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
func (fec *FEC) input(pkt fecPacket) (recovered [][]byte) {
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

	shardBegin := pkt.seqid - pkt.seqid%uint32(fec.shardSize)
	shardEnd := shardBegin + uint32(fec.shardSize) - 1

	searchBegin := insert_idx - fec.shardSize
	if searchBegin < 0 {
		searchBegin = 0
	}

	searchEnd := insert_idx + fec.shardSize
	if searchEnd >= len(fec.rx) {
		searchEnd = len(fec.rx) - 1
	}

	if len(fec.rx) >= fec.dataShards {
		shards := make([][]byte, fec.shardSize)
		numshard := 0
		first := -1
		maxlen := 0
		for i := searchBegin; i <= searchEnd; i++ {
			seqid := fec.rx[i].seqid
			if seqid >= shardBegin && seqid <= shardEnd {
				shards[seqid%uint32(fec.shardSize)] = fec.rx[i].data
				numshard++
				if numshard == 1 {
					first = i
				}
				if len(fec.rx[i].data) > maxlen {
					maxlen = len(fec.rx[i].data)
				}
			}
		}

		if numshard == fec.shardSize { // no lost
			copy(fec.rx[first:], fec.rx[first+numshard:])
			fec.rx = fec.rx[:len(fec.rx)-numshard]
		} else if numshard >= fec.dataShards { // recoverable
			// resize
			for k := range shards {
				if shards[k] != nil {
					shards[k] = shards[k][:maxlen]
				}
			}
			old := make([][]byte, fec.shardSize)
			copy(old, shards)
			if err := fec.enc.Reconstruct(shards); err == nil {
				for k := range old[:fec.dataShards] {
					if old[k] == nil {
						recovered = append(recovered, shards[k])
					}
				}
				copy(fec.rx[first:], fec.rx[first+numshard:])
				fec.rx = fec.rx[:len(fec.rx)-numshard]
			} else {
				log.Println(err)
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
	return
}

func (fec *FEC) calcECC(data [][]byte, offset, maxlen int) (ecc [][]byte) {
	if len(data) != fec.dataShards {
		println("mismatch", len(data), fec.dataShards)
		return nil
	}
	shards := make([][]byte, fec.shardSize)
	for k := range data {
		shards[k] = data[k][offset:maxlen]
	}

	for i := fec.dataShards; i < fec.shardSize; i++ {
		parity := make([]byte, maxlen)
		ecc = append(ecc, parity)
		shards[i] = parity[offset:maxlen]
	}

	if err := fec.enc.Encode(shards); err == nil {
		return ecc
	} else {
		log.Println(err)
	}
	return nil
}
