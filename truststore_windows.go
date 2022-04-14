// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/SpiderOak/wincertstore"
)

var (
	FirefoxProfile      = os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
	CertutilInstallHelp = "" // certutil unsupported on Windows
	NSSBrowsers         = "Firefox"
)

func (m *mkcert) installPlatform() bool {
	// Load cert
	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")
	// Decode PEM
	if certBlock, _ := pem.Decode(cert); certBlock == nil || certBlock.Type != "CERTIFICATE" {
		fatalIfErr(fmt.Errorf("invalid PEM data"), "decode pem")
	} else {
		cert = certBlock.Bytes
	}
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.Close()
	// Add cert
	fatalIfErr(store.AppendCertsFromPEM(cert), "add cert")
	return true
}

func (m *mkcert) uninstallPlatform() bool {
	// Load cert
	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")
	// Decode PEM
	if certBlock, _ := pem.Decode(cert); certBlock == nil || certBlock.Type != "CERTIFICATE" {
		fatalIfErr(fmt.Errorf("invalid PEM data"), "decode pem")
	} else {
		cert = certBlock.Bytes
	}
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.Close()
	// Do the deletion
	fatalIfErr(store.RemoveCertsFromPEM(cert), "remove certs")
	return true
}

func openWindowsRootStore() (*wincertstore.Store, error) {
	s, err := wincertstore.OpenSystemStore("ROOT")
	if err != nil {
		return nil, fmt.Errorf("unable to open Windows root store: %w", err)
	}
	return s, nil
}
