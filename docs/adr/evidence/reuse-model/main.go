package main

import (
	"fmt"
	"time"
)

// Round trips a fresh connection spends before it can issue MAIL FROM.
// TCP handshake 1.0, banner 0.5, EHLO 1.0, STARTTLS 1.0, TLS1.3 1.0, EHLO again 1.0.
const setupRTT = 5.5

// Round trips an RSET-reused connection spends before the same point.
const resetRTT = 1.0

// Round trips the mail transaction itself costs, identical under both strategies.
const txnRTT = 4.0

func perCell(rtt time.Duration, ratePerMin int, reuse bool) time.Duration {
	trips := setupRTT + txnRTT
	if reuse {
		trips = resetRTT + txnRTT
	}
	protocol := time.Duration(trips * float64(rtt))
	floor := time.Minute / time.Duration(ratePerMin)
	if floor > protocol {
		return floor
	}
	return protocol
}

func main() {
	cells := 18 // 3 envelope senders x 3 header froms x 2 helo identities
	rtts := []time.Duration{5 * time.Millisecond, 30 * time.Millisecond, 80 * time.Millisecond, 250 * time.Millisecond}
	rates := []int{6, 12, 30, 600}

	fmt.Printf("Matrix of %d cells. Wall clock for the whole run, fresh connection per cell vs RSET reuse.\n", cells)
	fmt.Printf("Model, not a capture: %.1f RTT of setup per fresh connection, %.1f for RSET, %.1f for the transaction.\n\n", setupRTT, resetRTT, txnRTT)
	fmt.Printf("%-8s %-10s %12s %12s %10s\n", "RTT", "rate/min", "fresh", "reuse", "saved")
	for _, r := range rates {
		for _, rtt := range rtts {
			f := time.Duration(cells) * perCell(rtt, r, false)
			u := time.Duration(cells) * perCell(rtt, r, true)
			pct := 100 * float64(f-u) / float64(f)
			fmt.Printf("%-8s %-10d %12s %12s %9.1f%%\n", rtt, r, f.Round(time.Millisecond), u.Round(time.Millisecond), pct)
		}
	}
	fmt.Println()
	fmt.Println("Binding constraint per row is whichever is larger, the protocol round trips or the rate-limit floor.")
}
