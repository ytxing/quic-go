package quic

import (
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type streamMapping struct {
	firstIncomingBidiStream protocol.StreamID
	firstIncomingUniStream  protocol.StreamID
	firstOutgoingBidiStream protocol.StreamID
	firstOutgoingUniStream  protocol.StreamID
}

var _ = Describe("Streams Map (for IETF QUIC)", func() {
	newFlowController := func(protocol.StreamID) flowcontrol.StreamFlowController {
		return mocks.NewMockStreamFlowController(mockCtrl)
	}

	serverStreamMapping := streamMapping{
		firstIncomingBidiStream: 4,
		firstOutgoingBidiStream: 1,
		firstIncomingUniStream:  2,
		firstOutgoingUniStream:  3,
	}
	clientStreamMapping := streamMapping{
		firstIncomingBidiStream: 1,
		firstOutgoingBidiStream: 4,
		firstIncomingUniStream:  3,
		firstOutgoingUniStream:  2,
	}

	for _, p := range []protocol.Perspective{protocol.PerspectiveServer, protocol.PerspectiveClient} {
		perspective := p
		var ids streamMapping
		if perspective == protocol.PerspectiveClient {
			ids = clientStreamMapping
		} else {
			ids = serverStreamMapping
		}

		Context(perspective.String(), func() {
			var m *streamsMap

			BeforeEach(func() {
				m = newStreamsMap(nil, newFlowController, perspective, versionIETFFrames).(*streamsMap)
			})

			Context("opening", func() {
				It("opens bidirectional streams", func() {
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&stream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					str, err = m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&stream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream + 4))
				})

				It("opens unidirectional streams", func() {
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&sendStream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream))
					str, err = m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&sendStream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream + 4))
				})
			})

			Context("accepting", func() {
				It("accepts bidirectional streams", func() {
					_, err := m.GetOrOpenReceiveStream(ids.firstIncomingBidiStream)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.AcceptStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&stream{}))
					Expect(str.StreamID()).To(Equal(ids.firstIncomingBidiStream))
				})

				It("accepts unidirectional streams", func() {
					_, err := m.GetOrOpenReceiveStream(ids.firstIncomingUniStream)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.AcceptUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&receiveStream{}))
					Expect(str.StreamID()).To(Equal(ids.firstIncomingUniStream))
				})
			})

			Context("deleting", func() {
				It("deletes outgoing bidirectional streams", func() {
					id := ids.firstOutgoingBidiStream
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenSendStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})

				It("deletes incoming bidirectional streams", func() {
					id := ids.firstIncomingBidiStream
					str, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})

				It("deletes outgoing unidirectional streams", func() {
					id := ids.firstOutgoingUniStream
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenSendStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})

				It("deletes incoming unidirectional streams", func() {
					id := ids.firstIncomingUniStream
					str, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})
			})

			Context("getting streams", func() {
				Context("send streams", func() {
					It("gets an outgoing bidirectional stream", func() {
						// need to open the stream ourselves first
						// the peer is not allowed to create a stream initiated by us
						_, err := m.OpenStream()
						Expect(err).ToNot(HaveOccurred())
						str, err := m.GetOrOpenSendStream(ids.firstOutgoingBidiStream)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					})

					It("errors when the peer tries to open a higher outgoing bidirectional stream", func() {
						id := ids.firstOutgoingBidiStream + 5*4
						_, err := m.GetOrOpenSendStream(id)
						Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("peer attempted to open stream %d", id))))
					})

					It("gets an outgoing unidirectional stream", func() {
						// need to open the stream ourselves first
						// the peer is not allowed to create a stream initiated by us
						_, err := m.OpenUniStream()
						Expect(err).ToNot(HaveOccurred())
						str, err := m.GetOrOpenSendStream(ids.firstOutgoingUniStream)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream))
					})

					It("errors when the peer tries to open a higher outgoing bidirectional stream", func() {
						id := ids.firstOutgoingUniStream + 5*4
						_, err := m.GetOrOpenSendStream(id)
						Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("peer attempted to open stream %d", id))))
					})

					It("gets an incoming bidirectional stream", func() {
						id := ids.firstIncomingBidiStream + 4*7
						str, err := m.GetOrOpenSendStream(id)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(id))
					})

					It("errors when trying to get an incoming unidirectional stream", func() {
						id := ids.firstIncomingUniStream
						_, err := m.GetOrOpenSendStream(id)
						Expect(err).To(MatchError(fmt.Errorf("peer attempted to open send stream %d", id)))
					})
				})

				Context("receive streams", func() {
					It("gets an outgoing bidirectional stream", func() {
						// need to open the stream ourselves first
						// the peer is not allowed to create a stream initiated by us
						_, err := m.OpenStream()
						Expect(err).ToNot(HaveOccurred())
						str, err := m.GetOrOpenReceiveStream(ids.firstOutgoingBidiStream)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					})

					It("errors when the peer tries to open a higher outgoing bidirectional stream", func() {
						id := ids.firstOutgoingBidiStream + 5*4
						_, err := m.GetOrOpenReceiveStream(id)
						Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("peer attempted to open stream %d", id))))
					})

					It("gets an incoming bidirectional stream", func() {
						id := ids.firstIncomingBidiStream + 4*7
						str, err := m.GetOrOpenReceiveStream(id)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(id))
					})

					It("gets an incoming unidirectional stream", func() {
						id := ids.firstIncomingUniStream + 4*10
						str, err := m.GetOrOpenReceiveStream(id)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(id))
					})

					It("errors when trying to get an outgoing unidirectional stream", func() {
						id := ids.firstOutgoingUniStream
						_, err := m.GetOrOpenReceiveStream(id)
						Expect(err).To(MatchError(fmt.Errorf("peer attempted to open receive stream %d", id)))
					})
				})
			})

			It("closes", func() {
				testErr := errors.New("test error")
				m.CloseWithError(testErr)
				_, err := m.OpenStream()
				Expect(err).To(MatchError(testErr))
				_, err = m.OpenUniStream()
				Expect(err).To(MatchError(testErr))
				_, err = m.AcceptStream()
				Expect(err).To(MatchError(testErr))
				_, err = m.AcceptUniStream()
				Expect(err).To(MatchError(testErr))
			})
		})
	}
})
