package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"arhat.dev/credentialfs/pkg/security"
)

func TestAuthorize(t *testing.T) {
	httptest.NewRecorder()
	mux := http.NewServeMux()

	uid := strconv.FormatInt(int64(os.Getuid()), 10)

	req, err := security.CreateAuthRequest(uid, uint64(os.Getpid()), security.OpRead, "foo")
	assert.NoError(t, err)

	mux.HandleFunc("/ok", func(rw http.ResponseWriter, r *http.Request) {
		recvAuthReq := &security.AuthRequest{}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		assert.NoError(t, dec.Decode(recvAuthReq))
		assert.EqualValues(t, req, recvAuthReq)
		rw.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/error", func(rw http.ResponseWriter, r *http.Request) {
		recvAuthReq := &security.AuthRequest{}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		assert.NoError(t, dec.Decode(recvAuthReq))
		assert.EqualValues(t, req, recvAuthReq)

		rw.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()

	okHandler := &authHandler{
		endpointURL: srv.URL + "/ok",
		client:      client,
	}
	assert.NoError(t, okHandler.Authorize(req), okHandler.endpointURL)

	failHandler := &authHandler{
		endpointURL: srv.URL + "/error",
		client:      client,
	}
	assert.Error(t, failHandler.Authorize(req), failHandler.endpointURL)
}
