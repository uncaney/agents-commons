// cx-b64: base64 / base64url / hex transcoding. Text protocol: first line is the command, the
// rest of the input is the payload (bytes, exactly as given):
//
//	encode | decode          standard base64 with padding
//	url-encode | url-decode  base64url without padding
//	hex | unhex              lowercase hex
//
// JSON form: {"op":"encode","in":"hello"}. Encoders print one line; decoders print the raw bytes.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

func main() {
	in := sio.Read()
	var op, payload string
	if m, ok := sio.Object(in); ok {
		op, payload = sio.Str(m, "op"), sio.Str(m, "in")
	} else {
		op, payload = sio.Line(in)
	}
	clean := strings.Join(strings.Fields(payload), "")
	switch op {
	case "encode":
		sio.Outln(base64.StdEncoding.EncodeToString([]byte(payload)))
	case "decode":
		b, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "=")); err != nil {
				sio.Fail("bad base64: " + err.Error())
			}
		}
		sio.Out(string(b))
	case "url-encode":
		sio.Outln(base64.RawURLEncoding.EncodeToString([]byte(payload)))
	case "url-decode":
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(clean, "="))
		if err != nil {
			sio.Fail("bad base64url: " + err.Error())
		}
		sio.Out(string(b))
	case "hex":
		sio.Outln(hex.EncodeToString([]byte(payload)))
	case "unhex":
		b, err := hex.DecodeString(strings.ToLower(strings.TrimPrefix(clean, "0x")))
		if err != nil {
			sio.Fail("bad hex: " + err.Error())
		}
		sio.Out(string(b))
	default:
		sio.Fail("usage: encode|decode|url-encode|url-decode|hex|unhex then the payload")
	}
}
