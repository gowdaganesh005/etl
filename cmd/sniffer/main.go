package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type DataEvent struct {
	CGroupId uint64
	Pid      uint32
	Len      uint32
	Payload  [256]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to RemoveMemlock :%v", err)

	}
	objs := snifferObjects{}
	if err := loadSnifferObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load BPF objects :%v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.Tracepoint, nil)
	if err != nil {
		log.Fatalf("failed to attach Tracepoint:%v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to ringbuf reader:%v", err)
	}
	defer rd.Close()

	logFile, err := os.OpenFile("output.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed to open output log file: %v ", err)
	}
	defer logFile.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nDetaching hook and exiting")
		rd.Close()

	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("error reading from the ringbuf: %v", err)
			continue
		}

		var event DataEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		length := int(event.Len)
		if length > len(event.Payload) {
			length = len(event.Payload)
		}

		rawText := strings.TrimSpace(string(event.Payload[:length]))
		cleanText := strings.ReplaceAll(rawText, "\n", " ")

		if len(rawText) > 0 {
			fmt.Fprintf(logFile, "PID: %-8d |BYTES %-4d | %s\n", event.Pid, length, cleanText)
		}

	}
}
