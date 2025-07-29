//go:build seed

package main

import (
	"crypto/rand"
	"fmt"
	"io"
)

func main() {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
	fmt.Print("[]byte{")
	for i, b := range salt {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("%d", b)
	}
	fmt.Println("}")
}
