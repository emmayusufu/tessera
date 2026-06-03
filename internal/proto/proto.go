// Package proto defines tessera's control messages and their length-prefixed framing.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const maxFrame = 1 << 16

type Kind string

const (
	KindRegister          Kind = "register"
	KindRequest           Kind = "request"
	KindDecision          Kind = "decision"
	KindOpenData          Kind = "open_data"
	KindDataHello         Kind = "data_hello"
	KindApprovalSubscribe Kind = "approval_subscribe"
	KindApprovalPrompt    Kind = "approval_prompt"
	KindApprovalDecision  Kind = "approval_decision"
	KindShareUpload       Kind = "share_upload"
	KindShareResponse     Kind = "share_response"
	KindSessionEnded      Kind = "session_ended"
)

type Msg struct {
	Kind Kind `json:"kind"`

	ShareID string `json:"share_id,omitempty"`
	Target  string `json:"target,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Who     string `json:"who,omitempty"`

	RequestID string `json:"request_id,omitempty"`
	Approved  bool   `json:"approved,omitempty"`
	Detail    string `json:"detail,omitempty"`

	SessionID string `json:"session_id,omitempty"`
	ConnID    string `json:"conn_id,omitempty"`
	Role      string `json:"role,omitempty"`

	Code string `json:"code,omitempty"`
}

func WriteMsg(w io.Writer, m Msg) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return fmt.Errorf("proto: frame too large (%d)", len(body))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func ReadMsg(r io.Reader) (Msg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Msg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return Msg{}, fmt.Errorf("proto: frame too large (%d)", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Msg{}, err
	}
	var m Msg
	if err := json.Unmarshal(body, &m); err != nil {
		return Msg{}, err
	}
	return m, nil
}
