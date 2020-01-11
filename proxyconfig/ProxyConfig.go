package proxyconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	url2 "net/url"
	"os"
	"strings"
)

type ProxyMapping struct {
	LocalPath  string `json:"localPath"`
	RemotePath string `json:"remotePath"`
	Host       string `json:"host"`
	UseHTTPS   bool   `json:"useHTTPS"`
	Port       int    `json:"port"`
}

func (proxyConfig *ProxyMapping) sanitize() {
	proxyConfig.LocalPath = strings.ToLower(strings.TrimSpace(proxyConfig.LocalPath))
	proxyConfig.RemotePath = strings.ToLower(strings.TrimSpace(proxyConfig.RemotePath))
	proxyConfig.Host = strings.ToLower(strings.TrimSpace(proxyConfig.Host))
	if proxyConfig.Port == 0 {
		if proxyConfig.UseHTTPS {
			proxyConfig.Port = 443
		} else {
			proxyConfig.Port = 80
		}
	}
}

type ProxyConfig struct {
	Mappings []*ProxyMapping
}

func (apiconfig *ProxyConfig) sanitize() {
	if apiconfig.Mappings != nil {
		for _, proxyConfig := range apiconfig.Mappings {
			proxyConfig.sanitize()
		}
	}
}

func ReadProxyConfig(filename string) (*ProxyConfig, error) {
	apiconfig := new(ProxyConfig)

	file, err := os.Open(filename)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error opening file %v: %v", filename, err))
	}

	defer file.Close()

	bytes, err := ioutil.ReadAll(file)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error reading file %v: %v", filename, err))
	}

	err = json.Unmarshal(bytes, apiconfig)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error parsing file %v: %v", filename, err))
	}

	err = validateAPIConfig(apiconfig)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error validating configuration file: %v", err))
	}

	apiconfig.sanitize()

	return apiconfig, nil
}

func validateAPIConfig(apiconfig *ProxyConfig) error {
	if len(apiconfig.Mappings) == 0 {
		return errors.New("No API mappings in configuration")
	}

	for _, proxyConfig := range apiconfig.Mappings {

		if len(strings.TrimSpace(proxyConfig.Host)) != len(proxyConfig.Host) {
			return errors.New(fmt.Sprintf("Host name contains whitespace: %v", proxyConfig.Host))
		}

		if len(strings.TrimSpace(proxyConfig.LocalPath)) != len(proxyConfig.LocalPath) {
			return errors.New(fmt.Sprintf("Local API contains whitespace: %v", proxyConfig.LocalPath))
		}

		if len(strings.TrimSpace(proxyConfig.RemotePath)) != len(proxyConfig.RemotePath) {
			return errors.New(fmt.Sprintf("Remote API contains whitespace: %v", proxyConfig.RemotePath))
		}

		if !strings.HasPrefix(proxyConfig.LocalPath, "/") {
			return errors.New(fmt.Sprintf("Local API does not begin with '/': %v", proxyConfig.LocalPath))
		}

		if !strings.HasPrefix(proxyConfig.RemotePath, "/") {
			return errors.New(fmt.Sprintf("Remote API does not begin with '/': %v", proxyConfig.RemotePath))
		}

		if proxyConfig.LocalPath != "/" && strings.HasSuffix(proxyConfig.LocalPath, "/") {
			return errors.New(fmt.Sprintf("Local API must not end with '/': %v", proxyConfig.LocalPath))
		}

		if proxyConfig.RemotePath != "/" && strings.HasSuffix(proxyConfig.RemotePath, "/") {
			return errors.New(fmt.Sprintf("Remote API must not end with '/': %v", proxyConfig.RemotePath))
		}

		url, err := url2.Parse("http://" + proxyConfig.Host)

		if err != nil {
			return errors.New(fmt.Sprintf("%v does not appear to be a valid host: %v", proxyConfig.Host, err))
		}

		if strings.Contains(proxyConfig.Host, ":") {
			return errors.New(
				fmt.Sprintf("Error in 'host' (%v). Value should be either a host name or ip address.  Ports are not allowed.  Use 'port' to specify a port. "+
					"If this an ipv6 address, note that these types of ip addresses are not yet supported.",
					proxyConfig.Host))
		}

		if strings.ToLower(url.Host) != strings.ToLower(proxyConfig.Host) {
			return errors.New(fmt.Sprintf("%v appears to contain superflous information.  It should be a simple host name or ip address", proxyConfig.Host))
		}
	}

	return nil
}
