package bitwarden

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"nhooyr.io/websocket"

	"arhat.dev/credentialfs/pkg/pm"
)

type syncCipherNotification struct {
	ID            string    `msgpack:"Id"`
	UserID        string    `msgpack:"UserId"`
	OrgID         string    `msgpack:"OrganizationId"`
	CollectionIds []string  `msgpack:"CollectionIds"`
	UpdatedAt     time.Time `msgpack:"Date"`
	RevisionDate  time.Time `msgpack:"RevisionDate"`
}

// startSyncing connects server websocket (SignalR)
func (d *Driver) startSyncing(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	var urlStr string
	if d.endpointURL == officialServiceEndpointURL {
		urlStr = fmt.Sprintf(
			"wss://%s/hub?access_token=%s",
			officialNotificationEndpointHost,
			d.accessToken,
		)
	} else {
		u, err := url.Parse(d.endpointURL)
		if err != nil {
			return err
		}

		urlStr = fmt.Sprintf(
			"wss://%s/%s?access_token=%s",
			u.Host,
			path.Join(d.endpointPathPrefix, "notifications/hub"),
			d.accessToken,
		)
	}

	conn, _, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{})
	if err != nil {
		return fmt.Errorf("failed to dial notification hub: %w", err)
	}

	err = conn.Write(ctx, websocket.MessageText, []byte(`{"protocol":"messagepack","version":1}`))
	if err != nil {
		return fmt.Errorf("failed to send initial message: %w", err)
	}

	msgType, initialResp, err := conn.Read(ctx)
	if err != nil {
		_ = conn.Close(websocket.StatusAbnormalClosure, "read failed")
		return fmt.Errorf("failed to receive initial response: %w", err)
	}

	if msgType != websocket.MessageBinary || !bytes.Equal(initialResp, []byte{'{', '}', 0x1e}) {
		_ = conn.Close(websocket.StatusAbnormalClosure, "invalid initial response")
		return fmt.Errorf("invalid initial response: %w", err)
	}

	go func() {
		tk := time.NewTicker(15 * time.Second)
		defer func() {
			tk.Stop()

			_ = conn.Close(websocket.StatusNormalClosure, "")
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				err := conn.Write(ctx, msgType, []byte{0x02, 0x91, 0x06})
				if err != nil {
					return
				}
			default:
			}

			msgType, data, err2 := conn.Read(ctx)
			if err2 != nil {
				// TODO: log error
				// fmt.Errorf("failed to read message: %w", err2)
				_ = d.startSyncing(ctx)
				return
			}

			if msgType != websocket.MessageBinary {
				// TODO: log error
				// fmt.Errorf("invalid message response type: not binary message")
				_ = d.startSyncing(ctx)
				return
			}

			// the server uses SignalR
			// https://dotnet.microsoft.com/apps/aspnet/signalr
			// so we need follow its wire protocol

			if bytes.Equal(data, []byte{0x02, 0x91, 0x06}) {
				// is keepalive
				continue
			}

			cipherUpdates, err := decodeSignalRMessage(data)
			if err != nil {
				// TODO: log error
				continue
			}

			if len(cipherUpdates) == 0 {
				continue
			}

			// TODO: log syncing

			// TODO: find a better to refresh cache
			err = d.buildCache(d.encKey, d.privateKey)
			if err != nil {
				// TODO: log re-sync error
				continue
			}

			d.Flush()

			var updates []*pm.CredentialUpdate
			for _, u := range cipherUpdates {
				emptyUpdates := d.subscriptions.PrepareUpdates(u.ID)

				for i, v := range emptyUpdates {
					ck := getCacheKey(v.Key)
					cv := d.cache.Get(ck.ItemName, ck.ItemKey)
					if cv == nil {
						// the cipher may be renamed
						continue
					}

					data := cv.Value
					if len(data) == 0 {
						// download attachment
						data, err = d.downloadAttachment(cv)
						if err != nil {
							// TODO: log error
							emptyUpdates[i].NotSynced = true
						}
					}

					emptyUpdates[i].NewValue = data

					updates = append(updates, emptyUpdates[i])
				}
			}

			for _, update := range updates {
				select {
				case <-ctx.Done():
					return
				case d.updateCh <- *update:
				}
			}
		}
	}()

	return nil
}

func decodeSignalRMessage(data []byte) ([]*syncCipherNotification, error) {
	const (
		target = "ReceiveMessage"
	)

	data = data[bytes.Index(data, []byte(target))+len(target):]
	dec := msgpack.NewDecoder(bytes.NewReader(data))
	args, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, fmt.Errorf("failed to decode invocation message: %w", err)
	}

	var result []*syncCipherNotification
	for i := 0; i < args; i++ {
		raw, err := dec.DecodeRaw()
		if err != nil {
			return nil, fmt.Errorf("failed to decode raw msg pack data: %w", err)
		}

		type notificationMessage struct {
			ContextID string `msgpack:"ContextId"`
			Type      int32  `msgpack:"Type"`

			// payload for syncCipherNotification
			Payload msgpack.RawMessage `msgpack:"Payload"`
		}

		msg := &notificationMessage{}
		err = msgpack.Unmarshal(raw, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to decode notification msg: %w", err)
		}

		// we only care about cipher updates
		// https://github.com/bitwarden/jslib/blob/master/common/src/enums/notificationType.ts

		const (
			syncCipherUpdate = 0
		)

		switch msg.Type {
		case syncCipherUpdate:
		default:
			continue
		}

		syncCipherMsg := &syncCipherNotification{}
		err = msgpack.Unmarshal(msg.Payload, syncCipherMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to decode cipher update notification: %w", err)
		}

		result = append(result, syncCipherMsg)
	}

	return result, nil
}
