package plugin

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestBitmap(t *testing.T) {
	var tempBitmap [(TC_MAX_CLASSID >> 5) + 1]uint32
	var number uint32
	bitmap := Bitmap(tempBitmap)
	bitmap.Reset()

	for i := 0; i <= TC_MAX_CLASSID; i++ {
		number = bitmap.FindFirstAvailable()
		assert.Equal(t, uint32(i), number, "FindFirstAvailable error")
		bitmap.AddNumber(number)
	}

	number = bitmap.FindFirstAvailable()
	assert.Equal(t, MAX_UINT32, number, "FindFirstAvailable error")

	bitmap.DelNumber(TC_MAX_CLASSID)
	number = bitmap.FindFirstAvailable()
	assert.Equal(t, uint32(TC_MAX_CLASSID), number, "FindFirstAvailable error")

	for i := 0; i < TC_MAX_CLASSID; i = i + 2 {
		bitmap.DelNumber(uint32(i))
	}

	for i := 0 ; i < TC_MAX_CLASSID; i = i + 2 {
		number = bitmap.FindFirstAvailable()
		assert.Equal(t, uint32(i), number, "FindFirstAvailable error")
		bitmap.AddNumber(number)
	}
}
/*
func TestInitInterfaceQosRule(t *testing.T) {
	eth1 := interfaceQosRules{name: "eth1"}
	eth1.InitInterfaceQosRule(INGRESS)
}


func TestAddFilter(t *testing.T)  {
	eth1 := interfaceQosRules
	rule1 := qosRule{ip: "10.86.1.72", port: 8001, bandwidth: 1024*1024}
	rule1.AddFilter("eth1", INGRESS)
}*/