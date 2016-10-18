package zvr

import "strings"

func FindNicNameByMac(mac string) (string, bool) {
	parser := NewParserFromShowConfiguration()

	config, ok := parser.GetConfig("interfaces ethernet")
	if !ok {
		return "", false
	}

	for _, eth := range config.Keys() {
		c, _ := config.GetConfig(eth)
		hw, ok := c.GetValue("hw-id")
		if !ok {
			continue
		}

		if strings.ToLower(mac) == hw {
			return eth, true
		}
	}

	return "", false
}

