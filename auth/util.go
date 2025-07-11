package auth

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// This is copied directly from Terraform in order to remove a single legacy
// vendor dependency.

const uaEnvVar = "TF_APPEND_USER_AGENT"

func terraformUserAgent(version, sdkVersion string) string {
	ua := fmt.Sprintf("HashiCorp Terraform/%s (+https://www.terraform.io)", version)
	if sdkVersion != "" {
		ua += " " + fmt.Sprintf("Terraform Plugin SDK/%s", sdkVersion)
	}

	if add := os.Getenv(uaEnvVar); add != "" {
		add = strings.TrimSpace(add)
		if len(add) > 0 {
			ua += " " + add
			log.Printf("[DEBUG] Using modified User-Agent: %s", ua)
		}
	}

	return ua
}

// PrepareTLSConfig generates TLS config based on the specifed parameters
func PrepareTLSConfig(caCertFile, clientCertFile, clientKeyFile string, insecure *bool) (*tls.Config, error) {
	config := &tls.Config{}
	if caCertFile != "" {
		caCert, _, err := pathOrContents(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("Error reading CA Cert: %s", err)
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(bytes.TrimSpace(caCert)); !ok {
			return nil, fmt.Errorf("Error parsing CA Cert from %s", caCertFile)
		}
		config.RootCAs = caCertPool
	}

	if insecure == nil {
		config.InsecureSkipVerify = false
	} else {
		config.InsecureSkipVerify = *insecure
	}

	if clientCertFile != "" && clientKeyFile != "" {
		clientCert, _, err := pathOrContents(clientCertFile)
		if err != nil {
			return nil, fmt.Errorf("Error reading Client Cert: %s", err)
		}
		clientKey, _, err := pathOrContents(clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("Error reading Client Key: %s", err)
		}

		cert, err := tls.X509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, err
		}

		config.Certificates = []tls.Certificate{cert}
		config.BuildNameToCertificate()
	}

	return config, nil
}

func pathOrContents(poc string) ([]byte, bool, error) {
	if len(poc) == 0 {
		return nil, false, nil
	}

	path := poc
	if path[0] == '~' {
		usr, err := user.Current()
		if err != nil {
			return []byte(path), true, err
		}

		if len(path) == 1 {
			path = usr.HomeDir
		} else if strings.HasPrefix(path, "~/") {
			path = filepath.Join(usr.HomeDir, path[2:])
		}
	}

	if _, err := os.Stat(path); err == nil {
		contents, err := os.ReadFile(path)
		if err != nil {
			return contents, true, err
		}
		return contents, true, nil
	}

	return []byte(poc), false, nil
}
