package wire

import (
	"bytes"
	"math/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// ComposeGQUICVersionNegotiation composes a Version Negotiation Packet for gQUIC
func ComposeGQUICVersionNegotiation(connID protocol.ConnectionID, versions []protocol.VersionNumber) []byte {
	fullReply := &bytes.Buffer{}
	ph := Header{
		ConnectionID: connID,
		PacketNumber: 1,
		VersionFlag:  true,
	}
	if err := ph.writePublicHeader(fullReply, protocol.PerspectiveServer, protocol.VersionWhatever); err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
		return nil
	}
	writeVersions(fullReply, versions)
	return fullReply.Bytes()
}

// ComposeVersionNegotiation composes a Version Negotiation according to the IETF draft
func ComposeVersionNegotiation(
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	versionOffered protocol.VersionNumber,
	versions []protocol.VersionNumber,
) []byte {
	fullReply := &bytes.Buffer{}
	ph := Header{
		IsLongHeader: true,
		Type:         protocol.PacketTypeVersionNegotiation,
		ConnectionID: connID,
		PacketNumber: pn,
		Version:      versionOffered,
	}
	if err := ph.writeHeader(fullReply); err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
		return nil
	}
	writeVersions(fullReply, versions)
	return fullReply.Bytes()
}

// writeVersions writes the versions for a Version Negotiation Packet.
// It inserts one reserved version number at a random position.
func writeVersions(buf *bytes.Buffer, versions []protocol.VersionNumber) {
	b := make([]byte, 1)
	_, _ = rand.Read(b) // ignore the error here. Failure to read random data doesn't break anything
	numVersions := len(versions)
	reservedVersion := protocol.GenerateReservedVersion()
	randPos := int(b[0]) % (numVersions + 1)
	for i, v := range versions {
		if i == randPos {
			utils.BigEndian.WriteUint32(buf, uint32(reservedVersion))
		}
		utils.BigEndian.WriteUint32(buf, uint32(v))
	}
	if randPos == numVersions {
		utils.BigEndian.WriteUint32(buf, uint32(reservedVersion))
	}
}
