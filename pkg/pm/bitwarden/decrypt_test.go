package bitwarden

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	test_email            = "test@example.com"
	test_masterPassword   = "testdata"
	test_pbkdf2Iterations = 400000

	test_masterPasswordHash = "DrDLENQU7xGRyGIQgmwtPPWUpmmNVX/nkP02TT2PyPw="

	test_masterKey          = "nMo7e5X+B83uTGX9ZEiwQjdJTIa9cmfX6uixTy/Uvgg="
	test_stretchedMasterKey = "xYJi1072jEjwT6+SqhdoearquKVH6aUc22tUiqPmugyGQl3NWrccivtmwq+VKR+YsYXefzlE0gU7Tabv1FUxsQ=="
	test_masterKeyEncKey    = "xYJi1072jEjwT6+SqhdoearquKVH6aUc22tUiqPmugw="
	test_masterKeyMacKey    = "hkJdzVq3HIr7ZsKvlSkfmLGF3n85RNIFO02m79RVMbE="

	test_symKey          = "EH18iFzBlsxefk4s3Dfy2nv/3SqfehYlv7I3Tj4YhwPG8ehNmOIawNiIDd966Bn2OJRoB1y0eQqEd83vWe5r6Q=="
	test_symKeyEncKey    = "EH18iFzBlsxefk4s3Dfy2nv/3SqfehYlv7I3Tj4YhwM="
	test_symKeyMac       = "xvHoTZjiGsDYiA3feugZ9jiUaAdctHkKhHfN71nua+k="
	test_protectedSymKey = "2.5xNi35zv1twQSQUeeDVsJw==|VcaCNhwXdbFW268B9OX/gBf3p/us3jcgl94Nph68qlyuu1S5P5WkBVOIVgmrYzHL7gV0s2eGEzrjv45dpvoZyO0srCXaXJYtxUmpFUJvoNM=|eFP/VgroWiD6ZwA+rH/0KrsQOchsB4hJ2t9shOTkjCg="

	test_publicKey           = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2EQW0Rl4AW/WbdIx39E4yT+5ugwUJqBjtMcYSU51V6X0qHfQoKcGi3Bir5dmOLL9hVh9fKeylAmTvTGCHBWEVq4Sufu2kIXJXTcduV9bIXPZIMGTRN4ybnLKRpnpLBltgOb7mq41obspbtDH53d5NcjhEPsxWBSYyYcTCkSOM/+DWsthmdP7efaaikpr3NR4OPlUkQ9b43yIW0XkbjD9yfs16ByGaainSmNEqHEdB8X2rjQIwRl/AD3P4ES/CRPAAJ9VZCdntIzR0C7utHkPcIiQmm7+3D8wZhe2KUpb/f1kt4K0aAKXt+KeTlHvpQN3Fb3KLe/3Whk5RjCg0xPr+wIDAQAB"
	test_privateKey          = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDYRBbRGXgBb9Zt0jHf0TjJP7m6DBQmoGO0xxhJTnVXpfSod9CgpwaLcGKvl2Y4sv2FWH18p7KUCZO9MYIcFYRWrhK5+7aQhcldNx25X1shc9kgwZNE3jJucspGmeksGW2A5vuarjWhuylu0Mfnd3k1yOEQ+zFYFJjJhxMKRI4z/4Nay2GZ0/t59pqKSmvc1Hg4+VSRD1vjfIhbReRuMP3J+zXoHIZpqKdKY0SocR0HxfauNAjBGX8APc/gRL8JE8AAn1VkJ2e0jNHQLu60eQ9wiJCabv7cPzBmF7YpSlv9/WS3grRoApe34p5OUe+lA3cVvcot7/daGTlGMKDTE+v7AgMBAAECggEAHZvA1fLbM7Mok9OFwYNG94KSfm696YXm8K6bXBnyRcQySUhSF1SWuEt0L18Wfye+Pt3dHE5nTA49nFblXcvyWN2vMahNF99BMNJlbuYnt15BeVMXQwP6upVbrSvQORnoHJBDHSvBqvlRVFsgK0f3n833Rlhlqo3zVw/3ot287FBMJl/u8Qg4RmvwK6FYM66qHASCYcjvuYYxCnkWDzElZLyU7hxYiP5aU9QDNRVVDNseIpmWUUiKP9c4X+bP58QSq7HZ6YUB0Rp8hoWgmt2V4u1X8tEH3eWRWOqXswY4MhlJgUcWSX+/4d4NBcjlEp65P0ZsRlIMQpodRe/0cuc0yQKBgQD0CYQ0KJXp8GHZVtz1pbZdcS81EXXWYYQyrwnVj/+kYBAVrx6olwWMsH7w6qDZh29dRCVNBhaHRSVC+Ko9fCU2pR6QjgqCOVWgvOMcD++u1uTdr/j1WSws5zBCOKyOFDsljdIFLJi4rRiYqPcnUTx0Lz7XwPYyT/5B8tz0wTUtYwKBgQDi3hChWmJPJb4qbG7vmjKNr7SZSqLLRMWpH4NUQ1/TKVojPdHlJU+KNjFVPJQSiSKvrVCD7SVN+JjASWPuOamxCYuX9bbFqldX2YBCpNEG/wjGlXdJjaWow/7Ciov+jOrYIiBtQBAr1Oi5qBiUNrzt32L8DFRw3e19ghy5NnF2iQKBgFmOwICvwEyJFi+/q/lOZj2mku+Dx930DaLYD+DbJrM5Oc3rZXHzcmruPrfFM2CBToJIxvOcX1onKwSH41oLHFEQicX9Cqg9yEnj5+jdhFWCsZ0VvmSz4/1anqA+0jyV+hrPEBssAaQMijFEGOfJ7UiqKgLd4rwWFTY4nZQI764HAoGBANvo1AgEG/2KoW5wE4zwVIahRhe9kFYnQM6yfFQmxvFiSTyWBSrw4swfwexUv1fEVLoj70MikiGlkzP5MAPRI1s33Hedt+CdQPMoIzr2lqQIfVI5uhqzUlxoOEANmqxRnqeJVRNxoPtL85dbiQ/Ki5KtEj8uGIAbr8UUZZFnY865AoGBAMj/ieRv782RkYrngx+Xh4WdMnEFKJBR0y+PD427hubJohotmmySzhC4RlzlfJS26rcDL1TQj2L9JrvVpRVXD/5WfGNCmFOSVjuYNqh1AAyok/smGY917ITYbDpnegKRS0qHEapRAx06cTQigdFxYv9/GY9KQ0RgmokgEMvVTOLE"
	test_protectedPrivateKey = "2.j4t3qxxbhSR1by5T/FSyUg==|8lUYUlWczcrRDbymPU2gea4fscuBIzxFavywHjXbwyBrROuLj/OLS76CPZKaOjWrJ1PgGlOatXBN6dHCvqZrfGBLFY/7UudrIjUZldVNR5Re6esxXyQPa+rNjT7+wY7xFl8JGHGZceTIbllIepWUhI9Rz4SoHkxpb7si9Qt/VRD23TAOe5bhicQ7MewCHzZzC3d4hzMkhaUTN/EZFdloKPZMqbCp0noc3UCtOFQPau1SB2SijOiruStdG3b7KTxXISxnbXHPnuFZYccYxkg4glne5yC99fbZxAXGimFOe6x9TwPrRraok83UFTXOljyrj53on5Ss7FwQykjk91OHKDbXzmM0keQBuPgC7IGd7sS/7rgFY0LXqslJWikxx7OGkNdTu9u1B6dIXwOe+yLk/lLQB6hthZCwXPdadA+QkIFzkICYssSSkMPMIrMKax6eqmJMvApbEtdiBC/lmfpRdJRRE/OlIeyD2dlyZPSoYRu9jhcQ0Q0cG4lG5M8j0cI5+uK31hl8fz6NljyZ9Ko5rPFlGw6SLzr+KX7Azq4yf/upXwJp4QFEtTrBtUUtqKy7d0god3MZx3xWGexpHT2ygct8HdM9yD8VipnjcIJbu0FSOwC9Re1ep/IY7HMxCQhD02fQcI2KhsygmApJoFsm1eGa9YeDkgHGkDXaOQizFz0eM+3+kGa7wRUnLkie/B+yKUm2nOI+9yXqE9B4auyseEyjZYPQgZEuzvB3SluRvoZc/Ui6gIM5VoC43vWDk8DILp35qEoI26H8L7A7R+aS4FyYhrnUWu4A36mQDxxbCbS0Hj1o1rWU0ejzmMlZtQ6VIvOXbTrwZmJhxe5bGqH8XZCE31UnYrV5cRtIS8Q62p6Sb4ErQ52EiR6xANxdZtFTOsO8X94EMndXtQ8yo/K06myjxMl4UUKzpe6mxP/wt+WwooPL/ikV1UKJQ/ZccvvV5L6KF0+klPxhOiZUqHqo94L53LSPM9iedo2gCG8f19sZ1ygP/GozeL56+nbemzYefCFzdJcnLpR1Tmcx7zrc/Lbo5PMPkOlNGg9HnurnZa005OlfcVxY/j3E6WRv2C9DGl+J3VcsjMe2ShKxfS92vzqOGyE/TMdG9GcboMCdZVLcj50e4M9ZDpVHEC66eX7mrMx0XPBtnALiwjNAvNFKkq9Y2pZVMXT9Kvk9qmlfteGqSSWnNk+8UGH1DggGzxTtL6XxIjRZGLC3qssoH/buVn5L9wOMgH02Vgash3c/M9b+jEJS3E6+H8c+bQ3tkhxTAc6Po2SfoBloseNVv31Q/x7AaOKepWQrdtGHK7OS3NR5bD7TjmUOg4FD/YtZh0GdO8zxBAb9Q4l0hI1Y1Ch11Fd7wFHZOdFi3BJnwLRqPzIDROeTNSlmEOj3jeuFJxXz/M3A/5Zc4aGZYN4bxczRYjjceNU+97GtTNRsgY+W9lD+bEr5cd0UcB5Rq5o9gf3HRczoVNjtP+0PQcayzfS0YxxcdWYKUpG2Z/iwRA6wsyKdlHvH74Dg5PJ9e5peLdPB/E1NrhoUBVRgXefBtXOUkUO+rsjTlVcTps1CX+V1X8R0mFWJxe/Qwg+QNiwL8RWxQxrQlM+XQ1JvtuyRsHEjHcIVdB2bFSNxYdg+/Cvbr3c=|MXUiwLAUqmFzjIB/BlNHOTZu18eHgi9LzQMG7cd+css="
)

func decodeB64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return data
}

func TestMakeMasterKey(t *testing.T) {
	data, err := makeMasterKey(
		[]byte(test_email),
		[]byte(test_masterPassword),
		KDFType_PBKDF2_SHA256,
		test_pbkdf2Iterations,
	)

	assert.NoError(t, err)
	assert.EqualValues(t, decodeB64(test_masterKey), data)
}

func TestMasterKeyStretchKey(t *testing.T) {
	decodeB64(test_masterKey)
}

func TestDecodeProtectedData(t *testing.T) {
	pd, err := decodeProtectedData(test_protectedSymKey)
	assert.NoError(t, err)
	_ = pd

	pd, err = decodeProtectedData(test_protectedPrivateKey)
	assert.NoError(t, err)
	_ = pd
}

// func TestDecryptRSA(t *testing.T) {
// 	pkData, err := decodeProtectedData("")
// 	assert.NoError(t, err)
// 	_ = pkData
//
// 	data, err := base64.StdEncoding.DecodeString("")
// 	assert.NoError(t, err)
//
// 	pk, err := x509.ParsePKCS8PrivateKey(data)
// 	assert.NoError(t, err)
//
// 	_ = pk.(*rsa.PrivateKey)
// }
