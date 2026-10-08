package e2e

import (
	"errors"
	"io"
)

// Sealed attachments and snapshot blobs (E2EE 7.3):
//
//	blob = s[32] | AES-256-GCM(HKDF(k_att, salt = s, "cx1/att", 32), 0^12, aad = "cx1/att", file)
//
// k_att is 32 random bytes carried in the {"t":"att"} control payload; a snapshot blob of a private
// group uses k_att = HKDF(msg_root_e, salt = s, "cx1/snap", 32) with the blob's own salt.

const AttCap = 16 << 20

var ErrAtt = errors.New("e2e: bad sealed attachment")

func attKey(kAtt, s []byte) []byte { return HKDF(kAtt, s, LabelAtt, 32) }

// SealAttachment seals file under k_att with a fresh salt; SealAttachmentWithSalt fixes the salt
// (snapshots derive k_att from it).
func SealAttachment(kAtt, file []byte, rnd io.Reader) ([]byte, error) {
	s := make([]byte, 32)
	if _, err := io.ReadFull(reader(rnd), s); err != nil {
		return nil, err
	}
	return SealAttachmentWithSalt(kAtt, s, file)
}

func SealAttachmentWithSalt(kAtt, s, file []byte) ([]byte, error) {
	if len(kAtt) != 32 || len(s) != 32 || len(file)+48 > AttCap {
		return nil, ErrAtt
	}
	g, err := gcm(attKey(kAtt, s))
	if err != nil {
		return nil, err
	}
	return cat(s, g.Seal(nil, zeroNonce, file, []byte(LabelAtt))), nil
}

// OpenAttachment reverses SealAttachment.
func OpenAttachment(kAtt, blob []byte) ([]byte, error) {
	if len(kAtt) != 32 || len(blob) < 48 || len(blob) > AttCap {
		return nil, ErrAtt
	}
	g, err := gcm(attKey(kAtt, blob[:32]))
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, zeroNonce, blob[32:], []byte(LabelAtt))
	if err != nil {
		return nil, ErrAtt
	}
	return pt, nil
}

// SnapshotKey is the k_att of a group snapshot blob for the blob's salt s.
func SnapshotKey(msgRoot, s []byte) []byte { return HKDF(msgRoot, s, LabelSnap, 32) }

// OpenSnapshot opens a snapshot blob sealed with SnapshotKey(msgRoot, blob[:32]).
func OpenSnapshot(msgRoot, blob []byte) ([]byte, error) {
	if len(blob) < 48 {
		return nil, ErrAtt
	}
	return OpenAttachment(SnapshotKey(msgRoot, blob[:32]), blob)
}

// AttManifest is the {"t":"att"} control payload (type 2, FlagATT).
type AttManifest struct {
	T string   `json:"t"`
	A []AttRef `json:"a"`
}

type AttRef struct {
	H   string `json:"h"`   // sha256 hex of the sealed blob
	K   string `json:"k"`   // base64url k_att
	N   string `json:"n"`   // name
	S   int64  `json:"s"`   // plaintext size
	Exp int64  `json:"exp"` // fetch-by (unix)
}
