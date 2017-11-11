package handshake

import (
	"bytes"
	"io"
	"net"
	"time"
)

// The CryptoStreamConn is used as the net.Conn passed to mint.
// The crypto quic.Stream is only initialized once we create a session.
// Before that, data from and for STREAM_FRAMEs are passed in and out via the readBuf and the writeBuf.
type CryptoStreamConn struct {
	remoteAddr net.Addr

	// the buffers are used before the session is initialized
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer

	// stream will be set once the session is initialized
	stream io.ReadWriter
}

var _ net.Conn = &CryptoStreamConn{}

func NewCryptoStreamConn(remoteAddr net.Addr) *CryptoStreamConn {
	return &CryptoStreamConn{remoteAddr: remoteAddr}
}

func (c *CryptoStreamConn) Read(b []byte) (int, error) {
	if c.stream != nil {
		return c.stream.Read(b)
	}
	n, err := c.readBuf.Read(b)
	if err == io.EOF {
		err = nil
	}
	return n, err
}

func (c *CryptoStreamConn) AddDataForReading(data []byte) {
	c.readBuf.Write(data)
}

func (c *CryptoStreamConn) Write(p []byte) (int, error) {
	if c.stream != nil {
		return c.stream.Write(p)
	}
	return c.writeBuf.Write(p)
}

func (c *CryptoStreamConn) GetDataForWriting() []byte {
	defer c.writeBuf.Reset()
	return c.writeBuf.Bytes()
}

func (c *CryptoStreamConn) SetStream(stream io.ReadWriter) {
	c.stream = stream
}

// Flush copies the contents of the write buffer to the stream
func (c *CryptoStreamConn) Flush() (int, error) {
	n, err := io.Copy(c.stream, &c.writeBuf)
	return int(n), err
}

func (c *CryptoStreamConn) Close() error                     { return nil }
func (c *CryptoStreamConn) LocalAddr() net.Addr              { return nil }
func (c *CryptoStreamConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *CryptoStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *CryptoStreamConn) SetWriteDeadline(time.Time) error { return nil }
func (c *CryptoStreamConn) SetDeadline(time.Time) error      { return nil }
