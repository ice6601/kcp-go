# ***kcp-go*** :signal_strength:
[![GoDoc][1]][2] [![Build Status][3]][4] [![Go Report Card][5]][6] [![Coverage Statusd][7]][8]

[1]: https://godoc.org/github.com/xtaci/kcp-go?status.svg
[2]: https://godoc.org/github.com/xtaci/kcp-go
[3]: https://travis-ci.org/xtaci/kcp-go.svg?branch=master
[4]: https://travis-ci.org/xtaci/kcp-go
[5]: https://goreportcard.com/badge/xtaci/kcp-go
[6]: https://goreportcard.com/report/xtaci/kcp-go
[7]: https://coveralls.io/repos/github/xtaci/kcp-go/badge.svg?branch=master
[8]: https://coveralls.io/github/xtaci/kcp-go?branch=master

A port of [KCP](https://github.com/skywind3000/kcp) in [golang](https://golang.org/) 

# ***Features*** :zap:
1. 100% compatible with original [skywind3000's](https://github.com/skywind3000) C version with modificiations.
2. Pure golang implementation of KCP in a ***single file***  [kcp.go](https://github.com/xtaci/kcp-go/blob/master/kcp.go).
2. Instead of container.List, kcp-go made use of ***cache friendly*** slice based internal queue.
3. Provides a basic [session manager](https://github.com/xtaci/kcp-go/blob/master/sess.go), compatible with [net.Conn](https://golang.org/pkg/net/#Conn) and [net.Listener](https://golang.org/pkg/net/#Listener).
4. Indepedent KCP code and session manager code, you can copy kcp.go to your project without session manager.
5. Support [FEC(Forward Error Correction)](https://en.wikipedia.org/wiki/Forward_error_correction) with [Reed-Solomon](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
6. Support packet level encryption with [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [TEA](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) and insecure SimpleXOR.

# ***Conventions*** :zap:
1. [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)  for packet delivery.
2. ```conv uint32``` in session manager is a ***random number*** initiated by client.
3. KCP doesn't define control messages like SYN/ACK/FIN/RST in TCP, a real world example is to use some ***multiplexing*** protocol over session, such as [yamux](https://github.com/hashicorp/yamux), see [kcptun](https://github.com/xtaci/kcptun) for example.

# ***Performance*** :zap:
```
  型号名称：	MacBook Pro
  型号标识符：	MacBookPro12,1
  处理器名称：	Intel Core i5
  处理器速度：	2.7 GHz
  处理器数目：	1
  核总数：	2
  L2 缓存（每个核）：	256 KB
  L3 缓存：	3 MB
  内存：	8 GB
```
```
$ go test -run Speed
new client 127.0.0.1:61165
total recv: 16777216
time for 16MB rtt with encryption 570.41176ms
&{BytesSent:33554432 BytesReceived:33554432 MaxConn:2 ActiveOpens:1 PassiveOpens:1 CurrEstab:1 InErrs:0 InCsumErrors:0 InSegs:42577 OutSegs:42641 OutBytes:48111336 RetransSegs:92 FastRetransSegs:92 LostSegs:0 RepeatSegs:0 FECRecovered:1 FECErrs:0 FECSegs:8514}
PASS
ok  	github.com/xtaci/kcp-go	0.600s
```
