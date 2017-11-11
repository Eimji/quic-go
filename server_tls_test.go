package quic

import (
	"bytes"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/mocks/handshake"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

var _ net.Conn = &mockConn{}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
	}
}

func (c mockConn) Read(b []byte) (int, error) {
	n, err := c.readBuf.Read(b)
	if err == io.EOF {
		err = nil
	}
	return n, err
}

func (c mockConn) Write(p []byte) (int, error)      { return c.writeBuf.Write(p) }
func (c mockConn) Close() error                     { panic("not implemented") }
func (c mockConn) LocalAddr() net.Addr              { panic("not implemented") }
func (c mockConn) RemoteAddr() net.Addr             { panic("not implemented") }
func (c mockConn) SetDeadline(time.Time) error      { panic("not implemented") }
func (c mockConn) SetReadDeadline(time.Time) error  { panic("not implemented") }
func (c mockConn) SetWriteDeadline(time.Time) error { panic("not implemented") }

var _ = Describe("Stateless TLS handling", func() {
	var (
		conn        *mockPacketConn
		server      *serverTLS
		sessionChan <-chan packetHandler
		mintTLS     *mockhandshake.MockMintTLS
		extHandler  *mocks.MockTLSExtensionHandler
		mintReply   io.Writer
	)

	BeforeEach(func() {
		mintTLS = mockhandshake.NewMockMintTLS(mockCtrl)
		extHandler = mocks.NewMockTLSExtensionHandler(mockCtrl)
		conn = &mockPacketConn{}
		config := &Config{
			Versions: []protocol.VersionNumber{protocol.VersionTLS},
		}
		var err error
		server, sessionChan, err = newServerTLS(conn, config, nil, testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		server.newMintConn = func(bc *handshake.CryptoStreamConn, v protocol.VersionNumber) (handshake.MintTLS, handshake.TLSExtensionHandler, error) {
			mintReply = bc
			return mintTLS, extHandler, nil
		}
	})

	getPacket := func(f wire.Frame) (*wire.Header, []byte) {
		hdrBuf := &bytes.Buffer{}
		hdr := &wire.Header{
			IsLongHeader: true,
			PacketNumber: 1,
			Version:      protocol.VersionTLS,
		}
		err := hdr.Write(hdrBuf, protocol.PerspectiveClient, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		hdr.Raw = hdrBuf.Bytes()
		aead, err := crypto.NewNullAEAD(protocol.PerspectiveClient, 0, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		buf := &bytes.Buffer{}
		err = f.Write(buf, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		return hdr, aead.Seal(nil, buf.Bytes(), 1, hdr.Raw)
	}

	It("sends a version negotiation packet if it doesn't support the version", func() {
		server.HandleInitial(nil, &wire.Header{Version: 0x1337}, nil)
		Expect(conn.dataWritten.Len()).ToNot(BeZero())
		hdr, err := wire.ParseHeaderSentByServer(bytes.NewReader(conn.dataWritten.Bytes()), protocol.VersionUnknown)
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.Type).To(Equal(protocol.PacketTypeVersionNegotiation))
		Expect(sessionChan).ToNot(Receive())
	})

	It("ignores packets with invalid contents", func() {
		hdr, data := getPacket(&wire.StreamFrame{StreamID: 10, Offset: 11, Data: []byte("foobar")})
		server.HandleInitial(nil, hdr, data)
		Expect(conn.dataWritten.Len()).To(BeZero())
		Expect(sessionChan).ToNot(Receive())
	})

	It("replies with a Retry packet, if a Cookie is required", func() {
		mintTLS.EXPECT().Handshake().Return(mint.AlertStatelessRetry).Do(func() {
			mintReply.Write([]byte("Retry with this Cookie"))
		})
		hdr, data := getPacket(&wire.StreamFrame{Data: []byte("Client Hello")})
		server.HandleInitial(nil, hdr, data)
		Expect(conn.dataWritten.Len()).ToNot(BeZero())
		hdr, err := wire.ParseHeaderSentByServer(bytes.NewReader(conn.dataWritten.Bytes()), protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.Type).To(Equal(protocol.PacketTypeRetry))
		Expect(sessionChan).ToNot(Receive())
	})

	It("replies with a Handshake packet and creates a session, if no Cookie is required", func() {
		mintTLS.EXPECT().Handshake().Return(mint.AlertNoAlert).Do(func() {
			mintReply.Write([]byte("Server Hello"))
		})
		mintTLS.EXPECT().Handshake().Return(mint.AlertNoAlert)
		mintTLS.EXPECT().State().Return(mint.StateServerNegotiated)
		mintTLS.EXPECT().State().Return(mint.StateServerWaitFlight2)
		extHandler.EXPECT().GetPeerParams().Return(&handshake.TransportParameters{})
		hdr, data := getPacket(&wire.StreamFrame{Data: []byte("Client Hello")})
		go func() {
			defer GinkgoRecover()
			server.HandleInitial(nil, hdr, data)
			Expect(conn.dataWritten.Len()).ToNot(BeZero())
			hdr, err := wire.ParseHeaderSentByServer(bytes.NewReader(conn.dataWritten.Bytes()), protocol.VersionTLS)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeHandshake))
		}()
		Eventually(sessionChan).Should(Receive())
	})
})
