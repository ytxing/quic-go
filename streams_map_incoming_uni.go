// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/cheekybits/genny

package quic

import (
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type incomingUniStreamsMap struct {
	mutex sync.RWMutex
	cond  sync.Cond

	streams map[protocol.StreamID]receiveStreamI

	nextStream    protocol.StreamID
	highestStream protocol.StreamID
	newStream     func(protocol.StreamID) receiveStreamI

	closeErr error
}

func newIncomingUniStreamsMap(nextStream protocol.StreamID, newStream func(protocol.StreamID) receiveStreamI) *incomingUniStreamsMap {
	m := &incomingUniStreamsMap{
		streams:    make(map[protocol.StreamID]receiveStreamI),
		nextStream: nextStream,
		newStream:  newStream,
	}
	m.cond.L = &m.mutex
	return m
}

func (m *incomingUniStreamsMap) AcceptStream() (receiveStreamI, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var str receiveStreamI
	for {
		var ok bool
		if m.closeErr != nil {
			return nil, m.closeErr
		}
		str, ok = m.streams[m.nextStream]
		if ok {
			break
		}
		m.cond.Wait()
	}
	m.nextStream += 4
	return str, nil
}

func (m *incomingUniStreamsMap) GetOrOpenStream(id protocol.StreamID) (receiveStreamI, error) {
	// if the id is smaller than the highest we accepted
	// * this stream exists in the map, and we can return it, or
	// * this stream was already closed, then we can return the nil
	if id <= m.highestStream {
		m.mutex.RLock()
		s := m.streams[id]
		m.mutex.RUnlock()
		return s, nil
	}

	m.mutex.Lock()
	var start protocol.StreamID
	if m.highestStream == 0 {
		start = m.nextStream
	} else {
		start = m.highestStream + 4
	}
	for newID := start; newID <= id; newID += 4 {
		m.streams[newID] = m.newStream(newID)
		m.cond.Signal()
	}
	m.highestStream = id
	s := m.streams[id]
	m.mutex.Unlock()
	return s, nil
}

func (m *incomingUniStreamsMap) DeleteStream(id protocol.StreamID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.streams[id]; !ok {
		return fmt.Errorf("Tried to delete unknown stream %d", id)
	}
	delete(m.streams, id)
	return nil
}

func (m *incomingUniStreamsMap) CloseWithError(err error) {
	m.mutex.Lock()
	m.closeErr = err
	m.mutex.Unlock()
	m.cond.Signal()
}
