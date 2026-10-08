package b017

// script.go - a port of the @bsv/sdk 2.8.11 `Script` chunk model (src/script/Script.ts), which b017's
// fingerprints and unlock layouts are written against: chunk counts, `chunk.data?.length`, the OP_RETURN tail.
// go-sdk's own decoder differs in edge cases, so the reference's semantics are reproduced here:
//   - parsing is lazy: a script made from bytes serialises back to exactly those bytes until its chunks are
//     replaced (toBinary returns the raw bytes);
//   - an OP_RETURN outside a conditional takes the rest of the script as its data;
//   - a truncated push keeps the bytes that are there;
//   - writeBin never produces OP_N: [] is OP_0, 1..75 bytes a direct push, then PUSHDATA1/2/4.

import (
	"encoding/hex"
	"errors"
	"strings"
)

// Opcodes the port names (values as in @bsv/sdk OP).
const (
	OP_0              = 0x00
	OP_PUSHDATA1      = 0x4c
	OP_PUSHDATA2      = 0x4d
	OP_PUSHDATA4      = 0x4e
	OP_1NEGATE        = 0x4f
	OP_IF             = 0x63
	OP_NOTIF          = 0x64
	OP_VERIF          = 0x65
	OP_VERNOTIF       = 0x66
	OP_ENDIF          = 0x68
	OP_RETURN         = 0x6a
	OP_DUP            = 0x76
	OP_EQUAL          = 0x87
	OP_EQUALVERIFY    = 0x88
	OP_HASH160        = 0xa9
	OP_HASH256        = 0xaa
	OP_CHECKSIG       = 0xac
	OP_CHECKSIGVERIFY = 0xad
)

// Chunk is one script chunk. Data == nil means the chunk has no data (TS `data: undefined`); a non-nil empty
// slice is TS `data: []` (an OP_RETURN with nothing after it, a zero-length PUSHDATA1).
type Chunk struct {
	Op   byte
	Data []byte
}

// Script mirrors the TS Script: chunks parsed on demand from raw bytes, raw bytes kept until chunks change.
type Script struct {
	chunks []Chunk
	parsed bool
	raw    []byte // serialised form; nil when it must be recomputed from chunks
}

// NewScript builds a script from chunks (TS `new Script(chunks)`).
func NewScript(chunks []Chunk) *Script {
	return &Script{chunks: chunks, parsed: true}
}

// ScriptFromBinary is TS `Script.fromBinary`: lazily parsed, serialises back to `b` exactly.
func ScriptFromBinary(b []byte) *Script {
	raw := make([]byte, len(b))
	copy(raw, b)
	return &Script{raw: raw}
}

// ScriptFromHex is TS `Script.fromHex`.
func ScriptFromHex(h string) (*Script, error) {
	if len(h) == 0 {
		return ScriptFromBinary(nil), nil
	}
	if len(h)%2 != 0 {
		return nil, errors.New("There is an uneven number of characters in the string which suggests it is not hex encoded.")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("Some elements in this string are not hex encoded.")
	}
	return &Script{raw: b}, nil
}

// MustScriptFromHex panics on bad hex; for embedded constants.
func MustScriptFromHex(h string) *Script {
	s, err := ScriptFromHex(h)
	if err != nil {
		panic(err)
	}
	return s
}

// Chunks returns the parsed chunks (TS `script.chunks`). The slice is the script's own; use SetChunks to change it.
func (s *Script) Chunks() []Chunk {
	if s == nil {
		return nil
	}
	if !s.parsed {
		s.chunks = parseChunks(s.raw)
		s.parsed = true
	}
	return s.chunks
}

// SetChunks replaces the chunks (TS `script.chunks = value`) and drops the cached bytes.
func (s *Script) SetChunks(c []Chunk) {
	s.chunks = c
	s.parsed = true
	s.raw = nil
}

// ToBinary is TS `toBinary`: the raw bytes while unparsed or unchanged, else the serialised chunks.
func (s *Script) ToBinary() []byte {
	if s == nil {
		return nil
	}
	if s.raw != nil {
		out := make([]byte, len(s.raw))
		copy(out, s.raw)
		return out
	}
	s.raw = serializeChunks(s.Chunks())
	if s.raw == nil {
		s.raw = []byte{}
	}
	out := make([]byte, len(s.raw))
	copy(out, s.raw)
	return out
}

// ToHex is TS `toHex`.
func (s *Script) ToHex() string { return hex.EncodeToString(s.ToBinary()) }

// WriteBin is TS `writeBin`: append one push of `bin` (OP_0 for empty, never OP_N).
func (s *Script) WriteBin(bin []byte) *Script {
	c := s.Chunks()
	var ch Chunk
	switch n := len(bin); {
	case n == 0:
		ch = Chunk{Op: OP_0}
	case n < OP_PUSHDATA1:
		ch = Chunk{Op: byte(n), Data: clone(bin)}
	case n < 1<<8:
		ch = Chunk{Op: OP_PUSHDATA1, Data: clone(bin)}
	case n < 1<<16:
		ch = Chunk{Op: OP_PUSHDATA2, Data: clone(bin)}
	default:
		ch = Chunk{Op: OP_PUSHDATA4, Data: clone(bin)}
	}
	s.SetChunks(append(append([]Chunk{}, c...), ch))
	return s
}

// ChunksFromBin is boltLib `scriptChunksFromBin`: one push of `data` (OP_0 for empty).
func ChunksFromBin(data []byte) []Chunk {
	return NewScript(nil).WriteBin(data).Chunks()
}

// ChunkData is boltLib `scriptChunk`: the data of chunk i, or [] (never nil).
func ChunkData(s *Script, i int) []byte {
	c := s.Chunks()
	if i < 0 || i >= len(c) || c[i].Data == nil {
		return []byte{}
	}
	return c[i].Data
}

func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func readPushdataLength(op byte, b []byte, pos int) (n int, newPos int, hasLength bool) {
	length := len(b)
	at := func(i int) int {
		if i < length {
			return int(b[i])
		}
		return 0
	}
	switch {
	case op > 0 && op < OP_PUSHDATA1:
		return int(op), pos, true
	case op == OP_PUSHDATA1:
		has := pos < length
		l := 0
		if has {
			l = at(pos)
			pos++
		}
		return l, pos, has
	case op == OP_PUSHDATA2:
		has := pos+1 < length
		l := at(pos) | at(pos+1)<<8
		return l, minInt(pos+2, length), has
	default: // OP_PUSHDATA4
		has := pos+3 < length
		l := uint32(at(pos)) | uint32(at(pos+1))<<8 | uint32(at(pos+2))<<16 | uint32(at(pos+3))<<24
		return int(l), minInt(pos+4, length), has
	}
}

func parseChunks(b []byte) []Chunk {
	chunks := []Chunk{}
	length := len(b)
	pos := 0
	inCond := 0
	for pos < length {
		op := b[pos]
		pos++
		if op == OP_RETURN && inCond == 0 {
			chunks = append(chunks, Chunk{Op: op, Data: clone(b[pos:length])})
			break
		}
		if op == OP_IF || op == OP_NOTIF || op == OP_VERIF || op == OP_VERNOTIF {
			inCond++
		} else if op == OP_ENDIF {
			inCond--
		}
		if op > 0 && op <= OP_PUSHDATA4 {
			n, np, _ := readPushdataLength(op, b, pos)
			pos = np
			end := pos + n
			if end > length || end < pos {
				end = length
			}
			chunks = append(chunks, Chunk{Op: op, Data: clone(b[pos:end])})
			pos = end
		} else {
			chunks = append(chunks, Chunk{Op: op})
		}
	}
	return chunks
}

func serializeChunks(chunks []Chunk) []byte {
	out := []byte{}
	for _, c := range chunks {
		out = append(out, c.Op)
		if c.Data == nil {
			continue
		}
		if c.Op == OP_RETURN {
			out = append(out, c.Data...)
			break
		}
		n := len(c.Data)
		switch {
		case c.Op < OP_PUSHDATA1:
			out = append(out, c.Data...)
		case c.Op == OP_PUSHDATA1:
			out = append(out, byte(n))
			out = append(out, c.Data...)
		case c.Op == OP_PUSHDATA2:
			out = append(out, byte(n), byte(n>>8))
			out = append(out, c.Data...)
		case c.Op == OP_PUSHDATA4:
			out = append(out, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
			out = append(out, c.Data...)
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// asmOps maps the opcode names the reference's ASM uses to their values (only what fromASM needs here: b017's
// own templates are embedded as hex, so this serves the few literal ASM strings in the library).
var asmOps = map[string]byte{"OP_CHECKSIGVERIFY": OP_CHECKSIGVERIFY, "OP_ENDIF": OP_ENDIF, "OP_EQUALVERIFY": OP_EQUALVERIFY,
	"OP_DUP": OP_DUP, "OP_HASH160": OP_HASH160, "OP_CHECKSIG": OP_CHECKSIG}

// scriptFromASM is TS `Script.fromASM` for the subset of tokens the library uses: known ops and hex pushes.
func scriptFromASM(asm string) *Script {
	var chunks []Chunk
	for _, t := range strings.Split(asm, " ") {
		if op, ok := asmOps[t]; ok {
			chunks = append(chunks, Chunk{Op: op})
			continue
		}
		if t == "0" {
			chunks = append(chunks, Chunk{Op: 0})
			continue
		}
		if len(t)%2 != 0 {
			t = "0" + t
		}
		b, err := hex.DecodeString(t)
		if err != nil {
			panic("invalid hex string in script")
		}
		op := byte(len(b))
		if len(b) >= OP_PUSHDATA1 {
			op = OP_PUSHDATA1
		}
		chunks = append(chunks, Chunk{Op: op, Data: b})
	}
	return NewScript(chunks)
}
