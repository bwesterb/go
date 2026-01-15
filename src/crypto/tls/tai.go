package tls

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type TrustAnchorIdentifier []byte

func (tai TrustAnchorIdentifier) segments() []uint32 {
	var res []uint32
	cur := uint32(0)
	for i := 0; i < len(tai); i++ {
		cur = (cur << 7) | uint32(tai[i]&0x7f)

		if tai[i]&0x80 == 0 {
			res = append(res, cur)
			cur = 0
		}
	}

	return res
}

func (tai TrustAnchorIdentifier) String() string {
	if tai == nil {
		return "nil"
	}

	var buf bytes.Buffer

	first := true
	for _, s := range tai.segments() {
		if !first {
			_, _ = fmt.Fprintf(&buf, ".")
		}
		first = false
		_, _ = fmt.Fprintf(&buf, "%d", s)
	}
	return buf.String()
}

func (tai *TrustAnchorIdentifier) UnmarshalText(text []byte) error {
	bits := strings.Split(string(text), ".")
	var segments []uint32
	for i, bit := range bits {
		v, err := strconv.ParseUint(bit, 10, 32)
		if err != nil {
			return fmt.Errorf("TrustAnchorIdentifier: subidentifier %d: %v", i, err)
		}
		segments = append(segments, uint32(v))
	}
	err := tai.FromSegments(segments)
	if err != nil {
		return err
	}
	if len(*tai) > 255 {
		return errors.New("OID: over 255 bytes")
	}
	return nil
}

func (tai TrustAnchorIdentifier) MarshalBinary() ([]byte, error) {
	if len(tai) == 0 {
		return nil, errors.New("can't marshal uninitialized TrustAnchorIdentifier")
	}

	ret := make([]byte, len(tai))
	copy(ret, tai)
	return ret, nil
}

func (tai *TrustAnchorIdentifier) UnmarshalBinary(buf []byte) error {
	if len(buf) > 255 {
		return errors.New("TrustAnchorIdentifier: over 255 bytes")
	}
	if len(buf) == 0 {
		return errors.New("TrustAnchorIdentifier: must have at least one segment")
	}

	cur := uint64(0)
	child := 0

	for i := 0; i < len(buf); i++ {
		if cur == 0 && (buf)[i] == 0x80 {
			return errors.New("TrustAnchorIdentifier: not normalized; starts with 0x80")
		}
		cur = (cur << 7) | uint64((buf)[i]&0x7f)

		if cur > 0xffffffff {
			return fmt.Errorf("TrustAnchorIdentifier: overflow of sub-identifier %d", child)
		}

		if (buf)[i]&0x80 == 0 {
			cur = 0
			child++
		} else if i == len(buf)-1 {
			return errors.New("TrustAnchorIdentifier: ends on continuation")
		}
	}

	*tai = make([]byte, len(buf))
	copy(*tai, buf)
	return nil
}

func (tai *TrustAnchorIdentifier) Equal(rhs *TrustAnchorIdentifier) bool {
	if rhs == nil {
		return false
	}
	if len(*tai) == len(*rhs) {
		for i, v := range *tai {
			if v != (*rhs)[i] {
				return false
			}
		}
		return true
	}
	return false
}

func (tai *TrustAnchorIdentifier) FromSegments(segments []uint32) error {
	if len(segments) == 0 {
		return errors.New("TrustAnchorIdentifier: must have at least one segment")
	}
	var buf bytes.Buffer
	for _, v := range segments {
		for j := 4; j >= 0; j-- {
			cur := v >> (j * 7)
			if cur != 0 || j == 0 {
				toWrite := byte(cur & 0x7f)
				if j != 0 {
					toWrite |= 0x80
				}
				buf.WriteByte(toWrite)
			}
		}
	}
	*tai = buf.Bytes()
	if len(*tai) > 255 {
		return errors.New("TrustAnchorIdentifier: over 255 bytes")
	}
	return nil
}

func unmarshalTrustAnchorIDList(s *cryptobyte.String) []TrustAnchorIdentifier {
	var ss cryptobyte.String
	ret := []TrustAnchorIdentifier{}
	if !s.ReadUint16LengthPrefixed(&ss) {
		return nil
	}
	for !ss.Empty() {
		var taiBytes cryptobyte.String
		if !ss.ReadUint8LengthPrefixed(&taiBytes) {
			return nil
		}
		var tai TrustAnchorIdentifier
		if tai.UnmarshalBinary([]byte(taiBytes)) != nil {
			return nil
		}
		ret = append(ret, tai)
	}

	return ret
}

func marshalTrustAnchorIDList(b *cryptobyte.Builder, ids []TrustAnchorIdentifier) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, id := range ids {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(id))
			})
		}
	})
}
