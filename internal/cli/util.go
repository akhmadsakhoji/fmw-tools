// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

// readLine reads up to a newline, one byte at a time so nothing after the
// line is consumed. The trailing CR/LF is removed.
func readLine(f *os.File) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for len(b) < 4096 {
		n, err := f.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			b = append(b, one[0])
		}
		if errors.Is(err, io.EOF) {
			if len(b) == 0 {
				return "", io.EOF
			}
			break
		}
		if err != nil {
			return "", err
		}
	}
	return strings.TrimRight(string(b), "\r"), nil
}

// parseArgs lets options come before or after the positional arguments
// ("verify backup.fmw --deep" as well as "verify --deep backup.fmw").
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // flag.Parse reports it.
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return positional, fs.Parse(flags)
}

// listFlag collects a repeatable option; commas also separate values.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

// size formats bytes like "1.5 GB" (decimal units, as file managers show them).
func size(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// thousands formats 1234567 as "1,234,567".
func thousands(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// progress draws one updating line on a terminal: bar, bytes, speed, time left.
type progress struct {
	mu      sync.Mutex
	w       io.Writer
	on      bool
	label   string
	total   int64
	done    int64
	start   time.Time
	last    time.Time
	width   int
	printed bool
}

func newProgress(w io.Writer, on bool, label string, total int64) *progress {
	return &progress{w: w, on: on && total > 0, label: label, total: total, start: time.Now()}
}

func (p *progress) add(n int64) {
	if !p.on {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done += n
	if time.Since(p.last) < 150*time.Millisecond && p.done < p.total {
		return
	}
	p.last = time.Now()
	p.draw()
}

func (p *progress) draw() {
	done := min(p.done, p.total)
	pct := float64(done) / float64(p.total)
	const width = 16 // The whole line stays under 80 columns.
	fill := int(pct * width)
	bar := strings.Repeat("█", fill) + strings.Repeat("░", width-fill)
	elapsed := time.Since(p.start).Seconds()
	line := fmt.Sprintf("%s %s %3.0f%%  %s / %s", p.label, bar, pct*100, size(done), size(p.total))
	if elapsed > 0.5 && done > 0 {
		speed := float64(done) / elapsed
		line += fmt.Sprintf("  %s/s", size(int64(speed)))
		if done < p.total {
			left := time.Duration(float64(p.total-done)/speed) * time.Second
			line += "  " + left.Round(time.Second).String() + " left"
		}
	}
	n := len([]rune(line))
	pad := max(0, p.width-n) // Only as much as the previous line was longer.
	fmt.Fprintf(p.w, "\r%s%s", line, strings.Repeat(" ", pad))
	p.width = n
	p.printed = true
}

func (p *progress) finish() {
	if !p.on || !p.printed {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.width))
}

// clean makes text from an archive safe to print on a terminal: control
// characters (escape sequences could retitle, clear or rewrite the screen)
// and bidirectional overrides (which can disguise a name) become "?".
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == unicode.ReplacementChar {
			return '?'
		}
		return r
	}, s)
}
