// ctl: one PUT and N GETs on the native node serving <dir>, straight over its control
// socket, so the native node is the initiator and nothing but this loop sits beside it.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

var sock string

func op(name string, parts ...[]byte) []byte {
	c, err := net.Dial("unix", sock)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	hello := make([]byte, 1)
	if _, err := io.ReadFull(c, hello); err != nil || hello[0] != 0 {
		panic(fmt.Sprintf("no hello: %v", err))
	}
	n := 1 + 1 + len(name) // appLen + opLen + op ("" app = the node's only app)
	for _, p := range parts {
		n += len(p)
	}
	head := make([]byte, 4, 6+len(name))
	binary.BigEndian.PutUint32(head, uint32(n))
	head = append(head, 0, byte(len(name)))
	head = append(head, name...)
	bufs := net.Buffers{head}
	for _, p := range parts {
		bufs = append(bufs, p)
	}
	if _, err := bufs.WriteTo(c); err != nil {
		panic(err)
	}
	st := make([]byte, 5)
	if _, err := io.ReadFull(c, st); err != nil {
		panic(err)
	}
	body := make([]byte, binary.BigEndian.Uint32(st[1:]))
	if _, err := io.ReadFull(c, body); err != nil {
		panic(err)
	}
	if st[0] != 0 {
		panic(name + ": " + string(body))
	}
	return body
}

func main() {
	sock = os.Args[1] + ".control"
	sizeMB, _ := strconv.Atoi(os.Args[2])
	gets, _ := strconv.Atoi(os.Args[3])
	const MiB = 1 << 20
	size := sizeMB * MiB
	file := make([]byte, size)
	rand.Read(file)

	t := time.Now()
	start := op("putStart")
	win := int(binary.BigEndian.Uint32(start))
	stream := start[4:8]
	for off := 0; ; off += win {
		op("putWindow", stream, file[off:min(off+win, size)])
		if off+win >= size {
			break
		}
	}
	res := op("putFinish", stream)
	s := time.Since(t).Seconds()
	key := res[:32]
	landed, intended := binary.BigEndian.Uint32(res[36:]), binary.BigEndian.Uint32(res[40:])
	root := res[48 : 48+binary.BigEndian.Uint32(res[44:])]
	fmt.Printf("PUT %.2f s  %.1f MB/s wire  %d/%d replicas\n", s, float64(2*size)/MiB/s, landed, intended)

	for i := 1; i <= gets; i++ {
		t = time.Now()
		g := op("getStart", key, root)
		fsize := int(binary.BigEndian.Uint64(g))
		gs := g[8:12]
		out := make([]byte, 0, fsize)
		for len(out) < fsize {
			part := op("getNext", gs)
			if len(part) == 0 {
				panic("get stream ended early")
			}
			out = append(out, part...)
		}
		s = time.Since(t).Seconds()
		ok := ""
		if !bytes.Equal(out, file) {
			ok = "  MISMATCH"
		}
		fmt.Printf("GET #%d %.2f s  %.1f MB/s%s\n", i, s, float64(size)/MiB/s, ok)
	}
}
