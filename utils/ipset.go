package utils

import (
	"encoding/xml"
	"fmt"
	log "github.com/Sirupsen/logrus"
)

const (
	IPSET_TYPE_HASH_IP  = "hash:ip"
	IPSET_TYPE_HASH_NET = "hash:net"
)

/*
  # sudo ipset list -o xml
<ipset name="eth3.in-1001-source">
  <type>hash:ip</type>
  <header>
    <family>inet</family>
    <hashsize>1024</hashsize>
    <maxelem>65536</maxelem>
    <memsize>344</memsize>
    <references>0</references>
  </header>
  <members>
    <member>1.1.1.1</member>
    <member>2.2.2.1</member>
    <member>1.1.1.2</member>
  </members>
</ipset>
<ipset name="eth3.in-1003-source">
  <type>hash:ip</type>
*/
type IpSetList struct {
	XMLName xml.Name `xml:"ipsets"`
	Ipsets  []*IpSet `xml:"ipset"`
}

type IpSet struct {
	Name      string   `xml:"name,attr"`
	IpSetType string   `xml:"type"`
	Member    []string `xml:"members>member"`
}

func GetCurrentIpSet() ([]*IpSet, error) {
	cmd := Bash{
		Command: fmt.Sprintf("ipset list -o xml"),
		Sudo:    true,
	}

	ret, o, _, err := cmd.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("ipset list failed %s", err.Error())
		return nil, err
	}

	o = "<ipsets>\n" + o + "</ipsets>\n"
	var ipSets IpSetList
	if err := xml.Unmarshal([]byte(o), &ipSets); err != nil {
		return nil, err
	}

	return ipSets.Ipsets, nil
}

func NewIPSet(name, ipsetType string) *IpSet {
	return &IpSet{Name: name, IpSetType: ipsetType}
}

func (s *IpSet) Create() error {
	cmd := Bash{
		Command: fmt.Sprintf("ipset create %s %s -exist; ipset flush %s", s.Name, s.IpSetType, s.Name),
		Sudo:    true,
	}

	ret, _, _, err := cmd.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("create ipset %s failed err: %v, ret: %d", s.Name, err, ret)
		return fmt.Errorf("create ipset %s failed err: %v, ret: %d", s.Name, err, ret)
	}

	return nil
}

func (s *IpSet) Destroy() error {
	cmd := Bash{
		Command: fmt.Sprintf("ipset destroy %s -exist", s.Name),
		Sudo:    true,
	}

	ret, _, _, err := cmd.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("destroy ipset %s failed err: %v, ret: %d", s.Name, err, ret)
		return fmt.Errorf("destroy ipset %s failed err: %v, ret: %d", s.Name, err, ret)
	}

	return nil
}

func (s *IpSet) AddMember(members []string) error {
	for _, m := range members {
		cmd := Bash{
			Command: fmt.Sprintf("ipset add %s %s -exist", s.Name, m),
			Sudo:    true,
		}

		ret, _, _, err := cmd.RunWithReturn()
		if err != nil || ret != 0 {
			log.Debugf("ipset add member %s member %s failed err: %v, ret: %d", s.Name, m, err, ret)
			return fmt.Errorf("ipset add member %s member %s failed err: %v, ret: %d", s.Name, m, err, ret)
		}

		s.Member = append(s.Member, m)
	}

	return nil
}

func (s *IpSet) DeleteMember(members []string) error {
	memberMap := make(map[string]string)
	for _, m := range members {
		cmd := Bash{
			Command: fmt.Sprintf("ipset del %s %s -exist", s.Name, m),
			Sudo:    true,
		}

		ret, _, _, err := cmd.RunWithReturn()
		if err != nil || ret != 0 {
			log.Debugf("ipset del name: %s member %s failed err: %v, ret: %d", s.Name, m, err, ret)
			return fmt.Errorf("ipset del name: %s member %s failed err: %v, ret: %d", s.Name, m, err, ret)
		}
		memberMap[m] = m
	}

	var mem []string
	for _, m := range s.Member {
		if _, ok := memberMap[m]; !ok {
			mem = append(mem, m)
		}
	}

	s.Member = mem

	return nil
}

func (s *IpSet) IsExist() bool {
	cmd := Bash{
		Command: fmt.Sprintf("ipset list -n %s", s.Name),
		Sudo:    true,
	}

	ret, _, _, err := cmd.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("ipset name: %s doesn't exist", s.Name)
		return false
	}

	return true
}

func (s *IpSet) Swap(dst *IpSet) bool {
	if !s.IsExist() {
		log.Debugf("ipset swap name %s doesn't exist", s.Name)
		return false
	}

	if !dst.IsExist() {
		log.Debugf("ipset swap name %s doesn't exist", dst.Name)
		return false
	}

	cmd := Bash{
		Command: fmt.Sprintf("ipset swap %s %s -exist ", s.Name, dst.Name),
		Sudo:    true,
	}
	ret, _, _, err := cmd.RunWithReturn()
	if err != nil || ret != 0 {
		log.Debugf("ipset swap from %s to %s error", s.Name, dst.Name)
		return false
	}

	return true
}

/* for hash:ip, when add a member 1.1.1.0/24, you will get 1.1.1.0 ~ 1.1.1.255 from ipset list
func (s *IpSet) IsEqual(o *IpSet) bool {
	if s.Name != o.Name {
		return false
	}

	if s.IpSetType != o.IpSetType {
		return false
	}

	if len(s.Member) != len(o.Member) {
		return false
	}

	sort.Strings(s.Member)
	sort.Strings(o.Member)

	for i, _ := range s.Member {
		if s.Member[i] != o.Member[i] {
			return false
		}
	}

	return true
}  */
