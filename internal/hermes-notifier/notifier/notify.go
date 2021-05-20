package notifier

import (
	"bytes"
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/ownmfa/api/go/api"
	"github.com/ownmfa/hermes/api/go/message"
	"github.com/ownmfa/hermes/internal/hermes-notifier/template"
	"github.com/ownmfa/hermes/pkg/hlog"
	"github.com/ownmfa/hermes/pkg/key"
	"github.com/ownmfa/hermes/pkg/metric"
	"github.com/ownmfa/hermes/pkg/queue"
	"google.golang.org/protobuf/proto"
)

const (
	smsExpire   = 2 * time.Minute
	emailExpire = 5 * time.Minute
)

// notifyMessages receives notification metadata, formats messages from
// application templates, and sends notifications.
func (not *Notifier) notifyMessages() {
	hlog.Info("notifyMessages starting processor")

	var processCount int
	for msg := range not.nInSub.C() {
		// Retrieve published message.
		metric.Incr("received", nil)
		nIn := &message.NotifierIn{}
		err := proto.Unmarshal(msg.Payload(), nIn)
		if err != nil {
			msg.Ack()

			if !bytes.Equal([]byte{queue.Prime}, msg.Payload()) {
				metric.Incr("error", map[string]string{"func": "unmarshal"})
				hlog.Errorf("notifyMessages proto.Unmarshal nIn, err: %+v, %v",
					nIn, err)
			}

			continue
		}

		// Trace IDs have been authenticated and are safe to copy.
		var traceID uuid.UUID
		copy(traceID[:], nIn.TraceId)

		// Set up logging fields.
		logFields := map[string]interface{}{
			"traceID":    traceID.String(),
			"orgID":      nIn.OrgId,
			"appID":      nIn.AppId,
			"identityID": nIn.IdentityId,
		}
		logger := hlog.WithFields(logFields)

		// Retrieve identity.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		identity, otp, err := not.identityDAO.Read(ctx, nIn.IdentityId,
			nIn.OrgId, nIn.AppId)
		cancel()
		if err != nil {
			msg.Requeue()
			metric.Incr("error", map[string]string{"func": "readidentity"})
			logger.Errorf("notifyMessages not.identityDAO.Read: %v", err)

			continue
		}

		// Increment HOTP counter before each use to prevent resending
		// the same unverified passcode, and also to invalidate the previous
		// passcode. This has the side effect of doubling the counter rate on
		// successful verifications.
		var counter int64
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		counter, err = not.cache.Incr(ctx, key.HOTPCounter(identity.OrgId,
			identity.AppId, identity.Id))
		cancel()
		if err != nil {
			msg.Requeue()
			metric.Incr("error", map[string]string{"func": "incr"})
			logger.Errorf("notifyMessages not.cache.Incr: %v", err)

			continue
		}

		// Generate passcode.
		passcode, err := otp.HOTP(counter)
		if err != nil {
			msg.Requeue()
			metric.Incr("error", map[string]string{"func": "hotp"})
			logger.Errorf("notifyMessages otp.HOTP: %v", err)

			continue
		}

		// Retrieve app.
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		app, err := not.appDAO.Read(ctx, nIn.AppId, nIn.OrgId)
		cancel()
		if err != nil {
			msg.Requeue()
			metric.Incr("error", map[string]string{"func": "readapp"})
			logger.Errorf("notifyMessages not.appDAO.Read: %v", err)

			continue
		}
		logger.Debugf("notifyMessages app: %+v", app)

		// Generate templates.
		subj, body, htmlBody, err := genTemplates(app, passcode)
		if err != nil {
			msg.Ack()
			logger.Errorf("notifyMessages genTemplates: %v", err)

			continue
		}

		// Set the passcode expiration. It is not necessary to check for
		// collisions here, but if one was found, that would be notable.
		expire := smsExpire
		if _, ok := identity.MethodOneof.(*api.Identity_EmailMethod); ok {
			expire = emailExpire
		}

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		ok, err := not.cache.SetIfNotExistTTL(ctx, key.Expire(identity.OrgId,
			identity.AppId, identity.Id, passcode), 1, expire)
		cancel()
		if err != nil || !ok {
			msg.Requeue()
			metric.Incr("error", map[string]string{"func": "setifnotexistttl"})
			logger.Errorf("notifyMessages set expiration collision or error: "+
				"%v, %v", ok, err)

			continue
		}

		// Send notification.
		switch m := identity.MethodOneof.(type) {
		case *api.Identity_SmsMethod:
			ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
			err = not.notify.SMS(ctx, m.SmsMethod.Phone, app.DisplayName,
				passcode)
			cancel()
			if err != nil {
				msg.Ack()
				metric.Incr("error", map[string]string{"func": "sms"})
				logger.Errorf("notifyMessages not.notify.SMS: %v", err)

				continue
			}
		case *api.Identity_PushoverMethod:
			ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
			if app.PushoverKey == "" {
				err = not.notify.Pushover(ctx, m.PushoverMethod.PushoverKey,
					app.DisplayName, passcode)
			} else {
				err = not.notify.PushoverByApp(ctx, app.PushoverKey,
					m.PushoverMethod.PushoverKey, subj, body)
			}
			cancel()
			if err != nil {
				msg.Ack()
				metric.Incr("error", map[string]string{"func": "sms"})
				logger.Errorf("notifyMessages not.notify.SMS: %v", err)

				continue
			}
		case *api.Identity_EmailMethod:
			ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
			err = not.notify.Email(ctx, app.DisplayName, app.Email,
				m.EmailMethod.Email, subj, body, htmlBody)
			cancel()
			if err != nil {
				msg.Ack()
				metric.Incr("error", map[string]string{"func": "email"})
				logger.Errorf("notifyMessages not.notify.Email: %v", err)

				continue
			}
		default:
			msg.Ack()
			metric.Incr("error", map[string]string{"func": "methodoneof"})
			logger.Errorf("notifyMessages unsupported identity.MethodOneof: "+
				"%+v", identity)

			continue
		}

		msg.Ack()
		metric.Incr("processed", nil)
		logger.Debugf("notifyMessages processed: %+v", identity)

		processCount++
		if processCount%100 == 0 {
			hlog.Infof("notifyMessages processed %v messages", processCount)
		}
	}
}

// genTemplates generates a notification subject, body, and HTML body.
func genTemplates(app *api.App, passcode string) (string, string, string,
	error) {
	subj, err := template.Generate(app.DisplayName, passcode,
		app.SubjectTemplate)
	if err != nil {
		metric.Incr("error", map[string]string{"func": "gensubject"})

		return "", "", "", err
	}

	body, err := template.Generate(app.DisplayName, passcode,
		app.TextBodyTemplate)
	if err != nil {
		metric.Incr("error", map[string]string{"func": "genbody"})

		return "", "", "", err
	}

	htmlBody, err := template.Generate(app.DisplayName, passcode,
		string(app.HtmlBodyTemplate))
	if err != nil {
		metric.Incr("error", map[string]string{"func": "genhtmlbody"})

		return "", "", "", err
	}

	return subj, body, htmlBody, nil
}
