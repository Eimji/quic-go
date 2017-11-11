package handshake

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CryptoStreamConn", func() {
	csc := &CryptoStreamConn{}

	It("reads from the read buffer, when no stream is set", func() {
		csc.AddDataForReading([]byte("foobar"))
		data := make([]byte, 4)
		n, err := csc.Read(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(data).To(Equal([]byte("foob")))
	})

	It("writes to the write buffer, when no stream is set", func() {
		csc.Write([]byte("foo"))
		Expect(csc.GetDataForWriting()).To(Equal([]byte("foo")))
		csc.Write([]byte("bar"))
		Expect(csc.GetDataForWriting()).To(Equal([]byte("bar")))
	})

	It("reads from the stream, if available", func() {
		csc.stream = &bytes.Buffer{}
		csc.stream.Write([]byte("foobar"))
		data := make([]byte, 3)
		n, err := csc.Read(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(data).To(Equal([]byte("foo")))
	})

	It("writes to the stream, if available", func() {
		stream := &bytes.Buffer{}
		csc.SetStream(stream)
		csc.Write([]byte("foobar"))
		Expect(stream.Bytes()).To(Equal([]byte("foobar")))
	})
})
