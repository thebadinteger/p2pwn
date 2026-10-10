package core

import (
	"fmt"
	"math/rand"
)

var motds = []string{
	"also try krushitel",
	"hacking is bad",
	"get p2pwned",
	"imagine trying XD",
	"why would you do that",
	"bradar delete this",
}

func RandomMOTD() string {
	return motds[rand.Intn(len(motds))]
}

func PrintBanner(nowStr string) {
	scanRed.Printf("[%s] p2pwn ", nowStr)
	fmt.Printf("- %s\n", RandomMOTD())
}
