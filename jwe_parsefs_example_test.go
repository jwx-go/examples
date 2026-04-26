package examples_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v4/jwe"
)

func Example_jwe_ParseFS() {
	// Same canonical sample JWE as Example_jwe_parse, written out to a
	// file and parsed back via jwe.ParseFS. alg=RSA-OAEP, enc=A256GCM.
	const src = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg.YWtQIqXd8VYpjBGZ.KmJpIgDVk-c0Ei4.94UMzAd_b8yQJq6e3R2a-g`

	f, err := os.CreateTemp(``, `jwe_parsefs_example-*.jwe`)
	if err != nil {
		fmt.Printf("failed to create temporary file: %s\n", err)
		return
	}
	defer os.Remove(f.Name())

	f.Write([]byte(src))
	f.Close()

	msg, err := jwe.ParseFS(os.DirFS(filepath.Dir(f.Name())), filepath.Base(f.Name()))
	if err != nil {
		fmt.Printf("failed to parse JWE message from file %q: %s\n", f.Name(), err)
		return
	}

	json.NewEncoder(os.Stdout).Encode(msg)
	// OUTPUT:
	// {"ciphertext":"KmJpIgDVk-c0Ei4","encrypted_key":"QoQNICnJzzytxWd9FOy6PgP2Qyh6HAPXWBXSdaWCX7upX_mzXBdR2r6zJgb-8HgAMJ9dXJvTaaoNq6J5JOOZMUprnPy08rwACkKK_lR363C380_LHlYmqDQGPoqUt97m2ZDUgfGDKv7ilw6SAQpGZ7e3eOY4g_qINmJ8HxOUBovV_D335SFGOiPeogYGobzGhnqFdQ3wTAdy_aLFXiN8SYpCwIx_GugrI1x2JzCZ6INV_VVvp6gzYIr6nUNooQt0EwnlrsNlaFHIemFMmNoOHSTKvgXI49ZCVpBSZ3fQEtQPMlq2RB099VCLDTofBTOJvlYo4VPA5uxbs5pHa3ULGg","header":{"alg":"RSA-OAEP"},"iv":"YWtQIqXd8VYpjBGZ","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","tag":"94UMzAd_b8yQJq6e3R2a-g"}
}
