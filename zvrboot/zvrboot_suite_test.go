package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestZvrboot(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Zvrboot Suite")
}
