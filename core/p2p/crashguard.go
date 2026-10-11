package p2p

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

func pipeCrashGuard() {
	r := recover()
	if r == nil {
		return
	}
	reason := fmt.Sprint(r)
	if i := len(reason); i > 200 {
		reason = reason[:200]
	}
	stack := debug.Stack()

	LogDebugf("crash", "worker panic > %s", reason)
	fmt.Fprintf(os.Stderr, "[!] worker panic: %s\n", reason)

	if dir := os.Getenv("P2PWN_CRASH_DIR"); dir != "" {
		name := filepath.Join(dir, fmt.Sprintf("crash_%d.txt", time.Now().Unix()))
		_ = os.WriteFile(name, []byte(reason+"\n\n"+string(stack)), 0644)
	}
	fmt.Fprint(os.Stderr, string(stack))
	os.Exit(2)
}
