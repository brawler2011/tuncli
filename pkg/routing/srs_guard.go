package routing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Check lengths before the upstream decoder allocates from untrusted varints.
// Only the domain-only subset accepted by ValidateSRS is admitted here. The
// pinned sing-box reader remains responsible for interpreting the rule data.
func guardSRS(expanded []byte) error {
	r := bytes.NewReader(expanded)
	if err := guardRules(r, 0); err != nil {
		return err
	}
	if r.Len() != 0 {
		return errors.New("trailing SRS rule data")
	}
	return nil
}
func boundedCount(r *bytes.Reader, limit int) (int, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}
	if n > uint64(limit) {
		return 0, errors.New("excessive SRS element count")
	}
	return int(n), nil
}
func skipSRS(r *bytes.Reader, size int) error {
	if size > r.Len() {
		return io.ErrUnexpectedEOF
	}
	_, err := r.Seek(int64(size), io.SeekCurrent)
	return err
}
func guardRules(r *bytes.Reader, depth int) error {
	if depth > 32 {
		return errors.New("SRS logical nesting too deep")
	}
	n, err := boundedCount(r, min(r.Len(), 65536))
	if err != nil {
		return err
	}
	for range n {
		kind, err := r.ReadByte()
		if err != nil {
			return err
		}
		switch kind {
		case 0:
			if err = guardDefault(r); err != nil {
				return err
			}
		case 1:
			mode, err := r.ReadByte()
			if err != nil {
				return err
			}
			if mode > 1 {
				return errors.New("invalid SRS logical mode")
			}
			if err = guardRules(r, depth+1); err != nil {
				return err
			}
			if _, err = r.ReadByte(); err != nil {
				return err
			}
		default:
			return errors.New("invalid SRS rule type")
		}
	}
	return nil
}
func guardDefault(r *bytes.Reader) error {
	seen := map[byte]bool{}
	for {
		kind, err := r.ReadByte()
		if err != nil {
			return err
		}
		if kind == 255 {
			_, err = r.ReadByte()
			return err
		}
		if seen[kind] {
			return errors.New("duplicate SRS predicate")
		}
		seen[kind] = true
		switch kind {
		case 2: // domain.Matcher: marker, two uint64 bitmaps, byte labels
			if _, err = r.ReadByte(); err != nil {
				return err
			}
			for _, width := range []int{8, 8, 1} {
				n, err := boundedCount(r, r.Len()/width)
				if err != nil {
					return err
				}
				if err = skipSRS(r, n*width); err != nil {
					return err
				}
			}
		case 3, 4: // domain keywords and regular expressions
			count, err := boundedCount(r, min(r.Len(), 65536))
			if err != nil {
				return err
			}
			for range count {
				size, err := boundedCount(r, r.Len())
				if err != nil {
					return err
				}
				if err = skipSRS(r, size); err != nil {
					return err
				}
			}
		default:
			return errors.New("SRS contains non-domain predicates")
		}
	}
}
