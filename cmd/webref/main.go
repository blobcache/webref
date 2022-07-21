package main

import "log"

func main() {
	c := NewRoot()
	if err := c.Execute(); err != nil {
		log.Fatal(err)
	}
}
