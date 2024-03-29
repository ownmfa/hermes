//go:build !unit

package queue

import (
	"fmt"
	"testing"
	"time"

	"github.com/ownmfa/hermes/pkg/test/config"
	"github.com/ownmfa/hermes/pkg/test/random"
	"github.com/stretchr/testify/require"
)

const testTimeout = 5 * time.Second

func TestNewNSQ(t *testing.T) {
	t.Parallel()

	testConfig := config.New()

	tests := []struct {
		inpPubAddr     string
		inpLookupAddrs []string
		err            string
	}{
		// Success.
		{testConfig.NSQPubAddr, nil, ""},
		{testConfig.NSQPubAddr, testConfig.NSQLookupAddrs, ""},
		// Wrong port.
		{"127.0.0.1:4152", nil, "connect: connection refused"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Can connect %+v", test), func(t *testing.T) {
			t.Parallel()

			res, err := NewNSQ(test.inpPubAddr, test.inpLookupAddrs,
				"testNewNSQ-"+random.String(10))
			t.Logf("res, err: %+v, %v", res, err)
			if test.err == "" {
				require.NotNil(t, res)
				require.NoError(t, err)
			} else {
				require.Contains(t, err.Error(), test.err)
			}
		})
	}
}

func TestNSQPublish(t *testing.T) {
	t.Parallel()

	testConfig := config.New()

	nsq, err := NewNSQ(testConfig.NSQPubAddr, testConfig.NSQLookupAddrs,
		"testNSQPublish-"+random.String(10))
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	require.NoError(t, nsq.Publish("testNSQPublish-"+random.String(10),
		random.Bytes(10)))

	nsq, err = NewNSQ(testConfig.NSQPubAddr, nil, "")
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	require.NoError(t, nsq.Publish("testNSQPublish-"+random.String(10),
		random.Bytes(10)))
}

func TestNSQSubscribeLookup(t *testing.T) {
	t.Parallel()

	testConfig := config.New()
	topic := "testNSQSubscribeLookup-" + random.String(10)
	payload := random.Bytes(10)

	nsq, err := NewNSQ(testConfig.NSQPubAddr, testConfig.NSQLookupAddrs,
		"testNSQSubscribeLookup-"+random.String(10))
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	// Publish before subscribe to allow for discovery by nsqlookupd.
	require.NoError(t, nsq.Publish(topic, payload))
	time.Sleep(100 * time.Millisecond)

	sub, err := nsq.Subscribe(topic)
	t.Logf("sub, err: %+v, %v", sub, err)
	require.NoError(t, err)

	select {
	case msg := <-sub.C():
		msg.Ack()
		t.Logf("msg.Topic, msg.Payload: %v, %x", msg.Topic(), msg.Payload())
		require.Equal(t, topic, msg.Topic())
		require.Equal(t, payload, msg.Payload())
	case <-time.After(testTimeout):
		t.Fatal("Message timed out")
	}
}

func TestNSQSubscribePub(t *testing.T) {
	t.Parallel()

	testConfig := config.New()
	topic := "testNSQSubscribePub-" + random.String(10)
	payload := random.Bytes(10)

	nsq, err := NewNSQ(testConfig.NSQPubAddr, nil,
		"testNSQSubscribePub-"+random.String(10))
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	sub, err := nsq.Subscribe(topic)
	t.Logf("sub, err: %+v, %v", sub, err)
	require.NoError(t, err)

	require.NoError(t, nsq.Publish(topic, payload))

	select {
	case msg := <-sub.C():
		msg.Ack()
		t.Logf("msg.Topic, msg.Payload: %v, %x", msg.Topic(), msg.Payload())
		require.Equal(t, topic, msg.Topic())
		require.Equal(t, payload, msg.Payload())
	case <-time.After(testTimeout):
		t.Fatal("Message timed out")
	}
}

func TestNSQPrime(t *testing.T) {
	t.Parallel()

	testConfig := config.New()
	topic := "testNSQPrime-" + random.String(10)

	nsq, err := NewNSQ(testConfig.NSQPubAddr, nil,
		"testNSQPrime-"+random.String(10))
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	sub, err := nsq.Subscribe(topic)
	t.Logf("sub, err: %+v, %v", sub, err)
	require.NoError(t, err)

	require.NoError(t, nsq.Prime(topic))

	select {
	case msg := <-sub.C():
		msg.Ack()
		t.Logf("msg.Topic, msg.Payload: %v, %x", msg.Topic(), msg.Payload())
		require.Equal(t, topic, msg.Topic())
		require.Equal(t, []byte{Prime}, msg.Payload())
	case <-time.After(testTimeout):
		t.Fatal("Message timed out")
	}
}

func TestNSQUnsubscribe(t *testing.T) {
	t.Parallel()

	testConfig := config.New()
	topic := "testNSQUnsubscribe-" + random.String(10)

	nsq, err := NewNSQ(testConfig.NSQPubAddr, testConfig.NSQLookupAddrs,
		"testNSQUnsubscribe-"+random.String(10))
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	sub, err := nsq.Subscribe(topic)
	t.Logf("sub, err: %+v, %v", sub, err)
	require.NoError(t, err)

	require.NoError(t, sub.Unsubscribe())

	// Publish after unsubscribe to verify closed sub.
	require.NoError(t, nsq.Publish("testNSQUnsubscribe-"+random.String(10),
		random.Bytes(10)))

	select {
	case msg, ok := <-sub.C():
		t.Logf("msg, ok: %#v, %v", msg, ok)
		require.Nil(t, msg)
		require.False(t, ok)
	case <-time.After(testTimeout):
		t.Fatal("Message timed out")
	}
}

func TestNSQRequeue(t *testing.T) {
	t.Parallel()

	testConfig := config.New()
	topic := "testNSQRequeue-" + random.String(10)
	payload := random.Bytes(10)

	nsq, err := NewNSQ(testConfig.NSQPubAddr, nil,
		"testNSQRequeue-"+random.String(10))
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	sub, err := nsq.Subscribe(topic)
	t.Logf("sub, err: %+v, %v", sub, err)
	require.NoError(t, err)

	require.NoError(t, nsq.Publish(topic, payload))

	// Skip redelivery. It can be painfully slow, even with lowered delay.
	select {
	case msg := <-sub.C():
		msg.Requeue()
		t.Logf("Requeue msg.Topic, msg.Payload: %v, %x", msg.Topic(),
			msg.Payload())
		require.Equal(t, topic, msg.Topic())
		require.Equal(t, payload, msg.Payload())
	case <-time.After(testTimeout):
		t.Fatal("Requeue message timed out")
	}
}

func TestNSQDisconnect(t *testing.T) {
	t.Parallel()

	testConfig := config.New()

	nsq, err := NewNSQ(testConfig.NSQPubAddr, testConfig.NSQLookupAddrs,
		"testNSQDisconnect-"+random.String(10))
	t.Logf("nsq, err: %+v, %v", nsq, err)
	require.NoError(t, err)

	nsq.Disconnect()
}
