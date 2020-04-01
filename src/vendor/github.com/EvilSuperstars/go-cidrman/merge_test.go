// go test -v -run="TestMergeCIDRs"

package cidrman

import (
	"reflect"
	"testing"
)

func TestMergeCIDRs(t *testing.T) {
	type TestCase struct {
		Input  []string
		Output []string
		Error  bool
	}

	testCases := []TestCase{
		{
			Input:  nil,
			Output: nil,
			Error:  false,
		},
		{
			Input:  []string{},
			Output: []string{},
			Error:  false,
		},
		{
			Input: []string{
				"10.0.0.0/8",
			},
			Output: []string{
				"10.0.0.0/8",
			},
			Error: false,
		},
		{
			Input: []string{
				"10.0.0.0/8",
				"0.0.0.0/0",
			},
			Output: []string{
				"0.0.0.0/0",
			},
			Error: false,
		},
		{
			Input: []string{
				"10.0.0.0/8",
				"10.0.0.0/8",
			},
			Output: []string{
				"10.0.0.0/8",
			},
			Error: false,
		},
		{
			Input: []string{
				"192.0.128.0/24",
				"192.0.129.0/24",
			},
			Output: []string{
				"192.0.128.0/23",
			},
			Error: false,
		},
		{
			Input: []string{
				"192.0.129.0/24",
				"192.0.130.0/24",
			},
			Output: []string{
				"192.0.129.0/24",
				"192.0.130.0/24",
			},
			Error: false,
		},
		{
			Input: []string{
				"192.0.2.112/30",
				"192.0.2.116/31",
				"192.0.2.118/31",
			},
			Output: []string{
				"192.0.2.112/29",
			},
			Error: false,
		},
		// The same as above out of order.
		{
			Input: []string{
				"192.0.2.116/31",
				"192.0.2.118/31",
				"192.0.2.112/30",
			},
			Output: []string{
				"192.0.2.112/29",
			},
			Error: false,
		},
		{
			Input: []string{
				"192.0.2.112/30",
				"192.0.2.116/32",
				"192.0.2.118/31",
			},
			Output: []string{
				"192.0.2.112/30",
				"192.0.2.116/32",
				"192.0.2.118/31",
			},
			Error: false,
		},
		{
			Input: []string{
				"192.0.2.112/31",
				"192.0.2.116/31",
				"192.0.2.118/31",
			},
			Output: []string{
				"192.0.2.112/31",
				"192.0.2.116/30",
			},
			Error: false,
		},
		{
			Input: []string{
				"192.0.1.254/31",
				"192.0.2.0/28",
				"192.0.2.16/28",
				"192.0.2.32/28",
				"192.0.2.48/28",
				"192.0.2.64/28",
				"192.0.2.80/28",
				"192.0.2.96/28",
				"192.0.2.112/28",
				"192.0.2.128/28",
				"192.0.2.144/28",
				"192.0.2.160/28",
				"192.0.2.176/28",
				"192.0.2.192/28",
				"192.0.2.208/28",
				"192.0.2.224/28",
				"192.0.2.240/28",
				"192.0.3.0/28",
			},
			Output: []string{
				"192.0.1.254/31",
				"192.0.2.0/24",
				"192.0.3.0/28",
			},
			Error: false,
		},
	}

	for _, testCase := range testCases {
		output, err := MergeCIDRs(testCase.Input)
		if err != nil {
			if !testCase.Error {
				t.Errorf("MergeCIDRS(%#v) failed: %s", testCase.Input, err.Error())
			}
		}
		if !reflect.DeepEqual(testCase.Output, output) {
			t.Errorf("MergeCIDRS(%#v) expected: %#v, got: %#v", testCase.Input, testCase.Output, output)
		}
	}
}
