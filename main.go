// acme-focused — 9P service that tracks the focused acme window.
//
// It watches the acme log for "focus" events and exposes the current focused
// window ID as a single file in a 9P filesystem posted to $NAMESPACE/acme-focused:
//
//	% 9p -a unix!$NAMESPACE/acme-focused read focus
//	42
//
// Designed to run as a launchd agent; see zip.connor.acmefocused.plist.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"9fans.net/go/acme"
	"9fans.net/go/plan9/client"
)

// focused holds the ID of the currently focused acme window.
var focused atomic.Int64

// focusedReady is closed once the first focus event has been received.
var (
	focusedOnce  sync.Once
	focusedReady = make(chan struct{})
)

func main() {
	log.SetPrefix("acme-focused: ")
	log.SetFlags(log.Ltime)

	srvPath := client.Namespace() + "/acme-focused"
	os.Remove(srvPath)

	l, err := net.Listen("unix", srvPath)
	if err != nil {
		log.Fatalf("listen %s: %v", srvPath, err)
	}
	defer l.Close()
	defer os.Remove(srvPath)

	fmt.Fprintln(os.Stderr, "acme-focused: listening on", srvPath)

	// Track the focused window by tailing the acme log.
	go trackFocus()

	// Clean up on signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Remove(srvPath)
		os.Exit(0)
	}()

	srv := &Server{}
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go srv.handleConn(c)
	}
}

// trackFocus tails the acme log indefinitely, restarting on error.
func trackFocus() {
	for {
		if err := watchLog(); err != nil {
			log.Printf("acme log: %v; retrying in 1s", err)
		}
		time.Sleep(time.Second)
	}
}

// watchLog opens the acme log and reads events until an error occurs.
func watchLog() error {
	alog, err := acme.Log()
	if err != nil {
		return err
	}
	defer alog.Close()
	for {
		ev, err := alog.Read()
		if err != nil {
			return err
		}
		switch ev.Op {
		case "focus":
			focused.Store(int64(ev.ID))
			focusedOnce.Do(func() { close(focusedReady) })
		case "del":
			// If the deleted window was the one we're tracking, clear it
			// so callers get 0 (no focused window) rather than a stale ID.
			focused.CompareAndSwap(int64(ev.ID), 0)
		}
	}
}
