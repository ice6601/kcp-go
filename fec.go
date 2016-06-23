package kcp

import (
	"encoding/binary"
	"log"

	"github.com/klauspost/reedsolomon"
)

const (
	fecHeaderSize      = 6
	fecHeaderSizePlus2 = fecHeaderSize + 2 // plus 2B data size
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
		shards       [][]byte
		shardsflag   []bool
		paws         uint32 // Protect Against Wrapped Sequence numbers
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
	fec.paws = (0xffffffff/uint32(fec.shardSize) - 1) * uint32(fec.shardSize)
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		log.Println(err)
		return nil
	}
	fec.enc = enc
	fec.shards = make([][]byte, fec.shardSize)
	fec.shardsflag = make([]bool, fec.shardSize)
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
	if fec.next >= fec.paws {
		fec.next = 0
	}
}

func (fec *FEC) markFEC(data []byte) {
	binary.LittleEndian.PutUint32(data, fec.next)
	binary.LittleEndian.PutUint16(data[4:], typeFEC)
	fec.next++
	if fec.next >= fec.paws {
		fec.next = 0
	}
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

	if len(fec.rx) >= fec.dataShards && shardBegin < shardEnd {
		numshard := 0
		numDataShard := 0
		first := -1
		maxlen := 0
		shards := fec.shards
		shardsflag := fec.shardsflag
		for k := range fec.shards {
			shards[k] = nil
			shardsflag[k] = false
		}

		for i := searchBegin; i <= searchEnd; i++ {
			seqid := fec.rx[i].seqid
			if seqid > shardEnd {
				break
			} else if seqid >= shardBegin {
				shards[seqid%uint32(fec.shardSize)] = fec.rx[i].data
				shardsflag[seqid%uint32(fec.shardSize)] = true
				numshard++
				if fec.rx[i].flag == typeData {
					numDataShard++
				}
				if numshard == 1 {
					first = i
				}
				if len(fec.rx[i].data) > maxlen {
					maxlen = len(fec.rx[i].data)
				}
			}
		}

		if numDataShard == fec.dataShards { // no lost
			copy(fec.rx[first:], fec.rx[first+numshard:])
			fec.rx = fec.rx[:len(fec.rx)-numshard]
		} else if numshard >= fec.dataShards { // recoverable
			for k := range shards {
				if shards[k] != nil {
					shards[k] = shards[k][:maxlen]
				}
			}
			if err := fec.enc.Reconstruct(shards); err == nil {
				for k := range shards[:fec.dataShards] {
					if !shardsflag[k] {
						recovered = append(recovered, shards[k])
					}
				}
			} else {
				log.Println(err)
			}
			copy(fec.rx[first:], fec.rx[first+numshard:])
			fec.rx = fec.rx[:len(fec.rx)-numshard]
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
	for k := range shards {
		if k < fec.dataShards {
			shards[k] = data[k][offset:maxlen]
		} else {
			parity := make([]byte, maxlen)
			ecc = append(ecc, parity)
			shards[k] = parity[offset:maxlen]
		}
	}

	if err := fec.enc.Encode(shards); err != nil {
		log.Println(err)
		return nil
	}
	return ecc
}
