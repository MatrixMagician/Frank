package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MatrixMagician/Frank/internal/smtptest"
)

type stubTB struct{}

func (stubTB) Helper()                   {}
func (stubTB) Errorf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
func (stubTB) Fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
func (stubTB) Cleanup(func())            {}

func main() {
	srv := smtptest.Start(stubTB{},
		smtptest.WithExtensions("SIZE 10240000", "8BITMIME", "ENHANCEDSTATUSCODES"),
		smtptest.RejectTriple(smtptest.PhaseEndOfData,
			smtptest.Triple{HeaderFrom: "ceo@victim.example"},
			550, "5.7.1", "sender address not owned by authenticated user"),
	)
	fmt.Println(srv.Addr())
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c
}
