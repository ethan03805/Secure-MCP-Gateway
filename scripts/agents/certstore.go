package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// certStoreEnv, set to 1, lets the suite add the Gateway CA to the Windows
// machine Root store for the run (and remove it afterwards). Only a
// disposable host sets it: the agents (windows) job of the Real agents
// workflow. Goose verifies TLS against the certificate store only on
// Windows, so without it Goose is recorded as not-run there.
const certStoreEnv = "SMCP_AGENTS_CERT_STORE"

// trustInMachineStore adds the PEM certificate at caPath to the
// LocalMachine Root store with certutil (the runner account is an
// administrator) and returns a function that deletes it again by serial
// number.
func trustInMachineStore(ctx context.Context, caPath string, logf func(string, ...any)) (func(), error) {
	b, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM certificate", caPath)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	serial := fmt.Sprintf("%x", cert.SerialNumber)
	if out, err := exec.CommandContext(ctx, "certutil", "-addstore", "-f", "Root", caPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("certutil -addstore Root: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	logf("added the Gateway CA (serial %s) to the LocalMachine Root store for this run", serial)
	return func() {
		out, err := exec.Command("certutil", "-delstore", "Root", serial).CombinedOutput()
		if err != nil {
			logf("certutil -delstore Root %s: %v: %s", serial, err, strings.TrimSpace(string(out)))
			return
		}
		logf("removed the Gateway CA (serial %s) from the LocalMachine Root store", serial)
	}, nil
}
