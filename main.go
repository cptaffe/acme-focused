// acme-focused — 9P service that tracks the focused acme window.
//
// It watches the acme log for "focus" events and exposes the current focused
// window ID as a single file in a 9P filesystem posted to $NAMESPACE/acme-focused:
//
//	% 9p read acme-focused/focus
//	42
//
// Designed to run under 9init; see the acme-focused.rc service in ~/lib/9init.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"9fans.net/go/acme"
	"9fans.net/go/plan9/srv9p"
	"github.com/cptaffe/p9srv"
)

// focused holds the ID of the currently focused acme window.
var focused atomic.Int64

// focusedReady is closed once the first focus event has been received.
var (
	focusedOnce  sync.Once
	focusedReady = make(chan struct{})
)

func buildServer() *srv9p.Server {
	tree := srv9p.NewTree("", "", 0555, nil)
	focusFile, err := tree.Root.Create("focus", "", 0444, nil)
	if err != nil {
		panic(err) // impossible: fresh tree
	}

	return &srv9p.Server{
		Tree: tree,
		Open: func(_ context.Context, fid *srv9p.Fid, _ uint8) error {
			if fid.File() == focusFile {
				// Non-blocking: if no focus event yet, return 0.
				select {
				case <-focusedReady:
				default:
				}
				fid.SetAux(fmt.Sprintf("%d\n", focused.Load()))
			}
			return nil
		},
		Read: func(_ context.Context, fid *srv9p.Fid, data []byte, offset int64) (int, error) {
			s, _ := fid.Aux().(string)
			return fid.ReadString(data, offset, s)
		},
	}
}

func main() {
	log.SetPrefix("acme-focused: ")
	log.SetFlags(log.Ltime)

	rw, cleanup, err := p9srv.Post("acme-focused")
	if err != nil {
		log.Fatalf("post: %v", err)
	}
	defer cleanup()

	log.Printf("serving at %s", p9srv.ServicePath("acme-focused"))

	go trackFocus()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cleanup()
		os.Exit(0)
	}()

	buildServer().Serve(rw, rw)
}

// trackFocus tails the acme log indefinitely, reconnecting on hard errors.
func trackFocus() {
	for {
		if err := watchLog(); err != nil {
			log.Printf("acme log: %v; retrying in 500ms", err)
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// watchLog opens the acme log and reads events until a hard error occurs.
func watchLog() error {
	alog, err := acme.Log()
	if err != nil {
		return err
	}
	defer alog.Close()
	for {
		ev, err := alog.Read()
		if err == io.EOF {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
		switch ev.Op {
		case "focus":
			focused.Store(int64(ev.ID))
			focusedOnce.Do(func() { close(focusedReady) })
		case "del":
			focused.CompareAndSwap(int64(ev.ID), 0)
		}
	}
}
