package handshake

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math"

	"github.com/lucas-clemente/quic-go/qerr"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type extensionHandlerServer struct {
	params     *TransportParameters
	paramsChan chan<- TransportParameters

	version           protocol.VersionNumber
	supportedVersions []protocol.VersionNumber
}

var _ mint.AppExtensionHandler = &extensionHandlerServer{}

func newExtensionHandlerServer(
	params *TransportParameters,
	paramsChan chan<- TransportParameters,
	supportedVersions []protocol.VersionNumber,
	version protocol.VersionNumber,
) *extensionHandlerServer {
	return &extensionHandlerServer{
		params:            params,
		paramsChan:        paramsChan,
		version:           version,
		supportedVersions: supportedVersions,
	}
}

func (h *extensionHandlerServer) Send(hType mint.HandshakeType, el *mint.ExtensionList) error {
	if hType != mint.HandshakeTypeEncryptedExtensions {
		return nil
	}

	transportParams := append(
		h.params.getTransportParameters(),
		// TODO(#855): generate a real token
		transportParameter{statelessResetTokenParameterID, bytes.Repeat([]byte{42}, 16)},
	)
	supportedVersions := h.getSupportedVersions()
	data, err := syntax.Marshal(encryptedExtensionsTransportParameters{
		SupportedVersions: supportedVersions,
		Parameters:        transportParams,
	})
	if err != nil {
		return err
	}
	return el.Add(&tlsExtensionBody{data})
}

// getSupportedVersions returns the supported versions as uint32
// It adds one reserved version at a random position.
func (h *extensionHandlerServer) getSupportedVersions() []uint32 {
	reservedVersion := protocol.GenerateReservedVersion()
	b := make([]byte, 1)
	_, _ = rand.Read(b) // ignore the error here. Failure to read random data doesn't break anything
	randPos := int(b[0]) % (len(h.supportedVersions) + 1)
	supportedVersions := make([]uint32, len(h.supportedVersions)+1)
	var j int
	for _, v := range h.supportedVersions {
		if j == randPos {
			supportedVersions[j] = uint32(reservedVersion)
			j++
		}
		supportedVersions[j] = uint32(v)
		j++
	}
	if randPos == len(h.supportedVersions) {
		supportedVersions[randPos] = uint32(reservedVersion)
	}
	return supportedVersions
}

func (h *extensionHandlerServer) Receive(hType mint.HandshakeType, el *mint.ExtensionList) error {
	ext := &tlsExtensionBody{}
	found := el.Find(ext)

	if hType != mint.HandshakeTypeClientHello {
		if found {
			return fmt.Errorf("Unexpected QUIC extension in handshake message %d", hType)
		}
		return nil
	}

	if !found {
		return errors.New("ClientHello didn't contain a QUIC extension")
	}
	chtp := &clientHelloTransportParameters{}
	if _, err := syntax.Unmarshal(ext.data, chtp); err != nil {
		return err
	}
	initialVersion := protocol.VersionNumber(chtp.InitialVersion)
	negotiatedVersion := protocol.VersionNumber(chtp.NegotiatedVersion)
	// check that the negotiated version is the version we're currently using
	if negotiatedVersion != h.version {
		return qerr.Error(qerr.VersionNegotiationMismatch, "Inconsistent negotiated version")
	}
	// perform the stateless version negotiation validation:
	// make sure that we would have sent a Version Negotiation Packet if the client offered the initial version
	// this is the case when the initial version is not contained in the supported versions
	if initialVersion != negotiatedVersion && protocol.IsSupportedVersion(h.supportedVersions, initialVersion) {
		return qerr.Error(qerr.VersionNegotiationMismatch, "Client should have used the initial version")
	}

	for _, p := range chtp.Parameters {
		if p.Parameter == statelessResetTokenParameterID {
			// TODO: return the correct error type
			return errors.New("client sent a stateless reset token")
		}
	}
	params, err := readTransportParamters(chtp.Parameters)
	if err != nil {
		return err
	}
	// TODO(#878): remove this when implementing the MAX_STREAM_ID frame
	params.MaxStreams = math.MaxUint32
	h.paramsChan <- *params
	return nil
}
