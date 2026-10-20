package main

import (
	"os"
	"time"
)

// consoleCloseBudget is how long smcpd takes at most after a console
// close, logoff or shutdown event: Windows ends the process about 5
// seconds after the event whatever the handler does (FR-21.7).
const consoleCloseBudget = 3500 * time.Millisecond

// onConsoleClose waits for the first signal on ch, then calls record (the
// journal stop record) and exit(0); when record has not returned within
// budget, exit(1) ends the process anyway, so it exits within 4 seconds of
// the event whatever the journal does. On Windows Go delivers CTRL_CLOSE,
// CTRL_LOGOFF and CTRL_SHUTDOWN as SIGTERM (main_windows.go); the backends
// end with their Job Objects' kill-on-close (FR-21.12).
func onConsoleClose(ch <-chan os.Signal, record func(), exit func(int), budget time.Duration) {
	<-ch
	t := time.AfterFunc(budget, func() { exit(1) })
	record()
	t.Stop()
	exit(0)
}
