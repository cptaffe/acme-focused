package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"9fans.net/go/plan9"
)

// ---------------------------------------------------------------------------
// File-type constants encoded into Qid.Path.
// ---------------------------------------------------------------------------

const (
	ftRoot  = uint64(0)
	ftFocus = uint64(1)
)

func makeQID(ft uint64) plan9.Qid {
	qt := uint8(plan9.QTFILE)
	if ft == ftRoot {
		qt = plan9.QTDIR
	}
	return plan9.Qid{Type: qt, Path: ft}
}

func makeDir(ft uint64) plan9.Dir {
	now := uint32(time.Now().Unix())
	switch ft {
	case ftRoot:
		return plan9.Dir{
			Qid:   makeQID(ftRoot),
			Mode:  plan9.DMDIR | 0555,
			Atime: now, Mtime: now,
			Name: "/", Uid: "none", Gid: "none", Muid: "none",
		}
	case ftFocus:
		return plan9.Dir{
			Qid:   makeQID(ftFocus),
			Mode:  0444,
			Atime: now, Mtime: now,
			Name: "focus", Uid: "none", Gid: "none", Muid: "none",
		}
	}
	panic("makeDir: unknown ft")
}

// ---------------------------------------------------------------------------
// 9P server — acme-styles dispatch pattern.
// ---------------------------------------------------------------------------

// Server holds no mutable state; all state is per-connection.
type Server struct{}

type fid struct {
	ft   uint64
	open bool
	mode uint8
	buf  []byte // content snapshot taken at Topen
}

type conn struct {
	srv   *Server
	c     net.Conn
	fids  map[uint32]*fid
	msize uint32
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	cn := &conn{
		srv:   s,
		c:     c,
		fids:  make(map[uint32]*fid),
		msize: 8192 + plan9.IOHDRSZ,
	}
	for {
		fc, err := plan9.ReadFcall(c)
		if err != nil {
			return
		}
		resp := cn.dispatch(fc)
		if err := plan9.WriteFcall(c, resp); err != nil {
			return
		}
	}
}

func rerr(tag uint16, msg string) *plan9.Fcall {
	return &plan9.Fcall{Type: plan9.Rerror, Tag: tag, Ename: msg}
}

func (cn *conn) dispatch(fc *plan9.Fcall) *plan9.Fcall {
	switch fc.Type {
	case plan9.Tversion:
		return cn.doVersion(fc)
	case plan9.Tauth:
		return rerr(fc.Tag, "no authentication required")
	case plan9.Tattach:
		return cn.doAttach(fc)
	case plan9.Tflush:
		return &plan9.Fcall{Type: plan9.Rflush, Tag: fc.Tag}
	case plan9.Twalk:
		return cn.doWalk(fc)
	case plan9.Topen:
		return cn.doOpen(fc)
	case plan9.Tcreate:
		return rerr(fc.Tag, "create not supported")
	case plan9.Tread:
		return cn.doRead(fc)
	case plan9.Twrite:
		return rerr(fc.Tag, "read only")
	case plan9.Tclunk:
		return cn.doClunk(fc)
	case plan9.Tremove:
		return rerr(fc.Tag, "remove not supported")
	case plan9.Tstat:
		return cn.doStat(fc)
	case plan9.Twstat:
		return rerr(fc.Tag, "wstat not supported")
	default:
		return rerr(fc.Tag, "unknown message type")
	}
}

func (cn *conn) doVersion(fc *plan9.Fcall) *plan9.Fcall {
	msize := fc.Msize
	if msize > cn.msize {
		msize = cn.msize
	}
	cn.msize = msize
	cn.fids = make(map[uint32]*fid)
	ver := "9P2000"
	if !strings.HasPrefix(fc.Version, "9P2000") {
		ver = "unknown"
	}
	return &plan9.Fcall{Type: plan9.Rversion, Tag: fc.Tag, Msize: msize, Version: ver}
}

func (cn *conn) doAttach(fc *plan9.Fcall) *plan9.Fcall {
	cn.fids[fc.Fid] = &fid{ft: ftRoot}
	return &plan9.Fcall{Type: plan9.Rattach, Tag: fc.Tag, Qid: makeQID(ftRoot)}
}

func (cn *conn) doWalk(fc *plan9.Fcall) *plan9.Fcall {
	f := cn.fids[fc.Fid]
	if f == nil {
		return rerr(fc.Tag, "fid unknown")
	}
	if f.open {
		return rerr(fc.Tag, "fid is open")
	}

	curFt := f.ft
	wqids := make([]plan9.Qid, 0, len(fc.Wname))

	for i, name := range fc.Wname {
		var nextFt uint64
		switch {
		case name == "..":
			nextFt = ftRoot
		case curFt == ftRoot && name == "focus":
			nextFt = ftFocus
		default:
			if i == 0 {
				return rerr(fc.Tag, "no such file")
			}
			goto done
		}
		wqids = append(wqids, makeQID(nextFt))
		curFt = nextFt
	}

done:
	newf := &fid{ft: curFt}
	if len(fc.Wname) == 0 {
		newf.ft = f.ft // clone
	}
	if len(wqids) == len(fc.Wname) {
		cn.fids[fc.Newfid] = newf
	}
	return &plan9.Fcall{Type: plan9.Rwalk, Tag: fc.Tag, Wqid: wqids}
}

func (cn *conn) doOpen(fc *plan9.Fcall) *plan9.Fcall {
	f := cn.fids[fc.Fid]
	if f == nil {
		return rerr(fc.Tag, "fid unknown")
	}
	if f.open {
		return rerr(fc.Tag, "already open")
	}
	mode := fc.Mode & 3

	switch f.ft {
	case ftRoot:
		if mode != plan9.OREAD {
			return rerr(fc.Tag, "is a directory")
		}
		// Directory listing: just the focus file.
		d := makeDir(ftFocus)
		b, _ := d.Bytes()
		f.buf = b

	case ftFocus:
		if mode != plan9.OREAD {
			return rerr(fc.Tag, "read only")
		}
		// Snapshot the current focused ID.  If no focus event has been
		// received yet this returns 0; callers should handle that.
		// We deliberately do not block: focus events arrive as mouse-over
		// events and should be available within milliseconds of acme
		// gaining focus.
		select {
		case <-focusedReady:
		default:
		}
		f.buf = []byte(fmt.Sprintf("%d\n", focused.Load()))
	}

	f.open = true
	f.mode = fc.Mode
	return &plan9.Fcall{
		Type:   plan9.Ropen,
		Tag:    fc.Tag,
		Qid:    makeQID(f.ft),
		Iounit: cn.msize - uint32(plan9.IOHDRSZ),
	}
}

func (cn *conn) doRead(fc *plan9.Fcall) *plan9.Fcall {
	f := cn.fids[fc.Fid]
	if f == nil {
		return rerr(fc.Tag, "fid unknown")
	}
	if !f.open {
		return rerr(fc.Tag, "not open")
	}
	off := fc.Offset
	n := fc.Count
	if off >= uint64(len(f.buf)) {
		return &plan9.Fcall{Type: plan9.Rread, Tag: fc.Tag}
	}
	end := off + uint64(n)
	if end > uint64(len(f.buf)) {
		end = uint64(len(f.buf))
	}
	return &plan9.Fcall{Type: plan9.Rread, Tag: fc.Tag, Data: f.buf[off:end]}
}

func (cn *conn) doClunk(fc *plan9.Fcall) *plan9.Fcall {
	delete(cn.fids, fc.Fid)
	return &plan9.Fcall{Type: plan9.Rclunk, Tag: fc.Tag}
}

func (cn *conn) doStat(fc *plan9.Fcall) *plan9.Fcall {
	f := cn.fids[fc.Fid]
	if f == nil {
		return rerr(fc.Tag, "fid unknown")
	}
	d := makeDir(f.ft)
	stat, err := d.Bytes()
	if err != nil {
		return rerr(fc.Tag, err.Error())
	}
	return &plan9.Fcall{Type: plan9.Rstat, Tag: fc.Tag, Stat: stat}
}
