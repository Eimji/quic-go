package wire

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// parseHeader parses the header.
func parseHeader(b *bytes.Reader, packetSentBy protocol.Perspective) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	if typeByte&0x80 > 0 {
		return parseLongHeader(b, packetSentBy, typeByte)
	}
	return parseShortHeader(b, typeByte)
}

// parse long header and version negotiation packets
func parseLongHeader(b *bytes.Reader, sentBy protocol.Perspective, typeByte byte) (*Header, error) {
	connID, err := utils.BigEndian.ReadUint64(b)
	if err != nil {
		return nil, err
	}
	v, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return nil, err
	}
	h := &Header{
		ConnectionID: protocol.ConnectionID(connID),
		Version:      protocol.VersionNumber(v),
	}
	if v == 0 { // version negotiation packet
		if sentBy == protocol.PerspectiveClient {
			return nil, qerr.InvalidVersion
		}
		if b.Len() == 0 {
			return nil, qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
		}
		h.IsVersionNegotiation = true
		h.SupportedVersions = make([]protocol.VersionNumber, b.Len()/4)
		for i := 0; b.Len() > 0; i++ {
			v, err := utils.BigEndian.ReadUint32(b)
			if err != nil {
				return nil, qerr.InvalidVersionNegotiationPacket
			}
			h.SupportedVersions[i] = protocol.VersionNumber(v)
		}
		return h, nil
	}
	h.IsLongHeader = true
	pn, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return nil, err
	}
	h.PacketNumber = protocol.PacketNumber(pn)
	h.PacketNumberLen = protocol.PacketNumberLen4
	h.Type = protocol.PacketType((typeByte ^ 0xff) + 1)
	if sentBy == protocol.PerspectiveClient && (h.Type != protocol.PacketTypeInitial && h.Type != protocol.PacketTypeHandshake && h.Type != protocol.PacketType0RTT) {
		return nil, qerr.Error(qerr.InvalidPacketHeader, fmt.Sprintf("Received packet with invalid packet type: %d", h.Type))
	}
	if sentBy == protocol.PerspectiveServer && (h.Type != protocol.PacketTypeRetry && h.Type != protocol.PacketTypeHandshake) {
		return nil, qerr.Error(qerr.InvalidPacketHeader, fmt.Sprintf("Received packet with invalid packet type: %d", h.Type))
	}
	return h, nil
}

func parseShortHeader(b *bytes.Reader, typeByte byte) (*Header, error) {
	hasConnID := typeByte&0x40 > 0
	var connID uint64
	if hasConnID {
		var err error
		connID, err = utils.BigEndian.ReadUint64(b)
		if err != nil {
			return nil, err
		}
	}
	pnLen := 1 << ((typeByte & 0xF) ^ 0xF)
	pn, err := utils.BigEndian.ReadUintN(b, uint8(pnLen))
	if err != nil {
		return nil, err
	}
	return &Header{
		SpinBit:          typeByte&0x10 != 0,
		KeyPhase:         int(typeByte&0x20) >> 5,
		OmitConnectionID: !hasConnID,
		ConnectionID:     protocol.ConnectionID(connID),
		PacketNumber:     protocol.PacketNumber(pn),
		PacketNumberLen:  protocol.PacketNumberLen(pnLen),
	}, nil
}

// writeHeader writes the Header.
func (h *Header) writeHeader(b *bytes.Buffer) error {
	if h.IsLongHeader {
		return h.writeLongHeader(b)
	}
	return h.writeShortHeader(b)
}

// TODO: add support for the key phase
func (h *Header) writeLongHeader(b *bytes.Buffer) error {
	b.WriteByte(byte((h.Type - 1) ^ 0xFF))
	utils.BigEndian.WriteUint64(b, uint64(h.ConnectionID))
	utils.BigEndian.WriteUint32(b, uint32(h.Version))
	utils.BigEndian.WriteUint32(b, uint32(h.PacketNumber))
	return nil
}

func (h *Header) writeShortHeader(b *bytes.Buffer) error {
	typeByte := byte(h.KeyPhase << 5)
	if h.SpinBit {
		typeByte ^= 0x10
	}
	if !h.OmitConnectionID {
		typeByte ^= 0x40
	}
	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		typeByte ^= 0xF
	case protocol.PacketNumberLen2:
		typeByte ^= 0xE
	case protocol.PacketNumberLen4:
		typeByte ^= 0xD
	default:
		return fmt.Errorf("invalid packet number length: %d", h.PacketNumberLen)
	}
	b.WriteByte(typeByte)

	if !h.OmitConnectionID {
		utils.BigEndian.WriteUint64(b, uint64(h.ConnectionID))
	}
	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(h.PacketNumber))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(h.PacketNumber))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(h.PacketNumber))
	}
	return nil
}

// getHeaderLength gets the length of the Header in bytes.
func (h *Header) getHeaderLength() (protocol.ByteCount, error) {
	if h.IsLongHeader {
		return 1 + 8 + 4 + 4, nil
	}

	length := protocol.ByteCount(1) // type byte
	if !h.OmitConnectionID {
		length += 8
	}
	if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 {
		return 0, fmt.Errorf("invalid packet number length: %d", h.PacketNumberLen)
	}
	length += protocol.ByteCount(h.PacketNumberLen)
	return length, nil
}

func (h *Header) logHeader() {
	if h.IsLongHeader {
		utils.Debugf("   Long Header{Type: %s, ConnectionID: %#x, PacketNumber: %#x, Version: %s}", h.Type, h.ConnectionID, h.PacketNumber, h.Version)
	} else {
		connID := "(omitted)"
		if !h.OmitConnectionID {
			connID = fmt.Sprintf("%#x", h.ConnectionID)
		}
		var b2i = map[bool]int{false: 0, true: 1}
		utils.Debugf("   Short Header{Spin bit: %d, ConnectionID: %s, PacketNumber: %#x, PacketNumberLen: %d, KeyPhase: %d}", b2i[h.SpinBit], connID, h.PacketNumber, h.PacketNumberLen, h.KeyPhase)
	}
}
