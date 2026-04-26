package examples_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_parse() {
	// A sample compact-serialized JWE produced with alg=RSA-OAEP and
	// enc=A256GCM. The five dot-separated segments are
	// protected-header / encrypted-key / iv / ciphertext / tag.
	const src = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg.YWtQIqXd8VYpjBGZ.KmJpIgDVk-c0Ei4.94UMzAd_b8yQJq6e3R2a-g`

	msg, err := jwe.Parse([]byte(src))
	if err != nil {
		fmt.Printf("failed to parse JWE message: %s\n", err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(msg)
	// OUTPUT:
	// {"ciphertext":"KmJpIgDVk-c0Ei4","encrypted_key":"QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg","header":{"alg":"RSA-OAEP"},"iv":"YWtQIqXd8VYpjBGZ","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","tag":"94UMzAd_b8yQJq6e3R2a-g"}
}
