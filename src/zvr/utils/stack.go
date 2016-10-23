package utils

type Stack struct {
	top *node
	size int
}

type node struct {
	value interface{}
	next *node
}

func (s *Stack) Len() int {
	return s.size
}

func (s *Stack) Push(value interface{}) {
	s.top = &node{value, s.top}
	s.size++
}

func (s *Stack) Pop() (value interface{}) {
	if s.size > 0 {
		value, s.top = s.top.value, s.top.next
		s.size--
		return
	}

	return nil
}

func (s *Stack) Slice() []interface{} {
	ret := make([]interface{}, 0)
	c := s.top
	for {
		if c == nil {
			return ret
		}

		ret = append(ret, c.value)
		c = c.next
	}
}

func (s *Stack) ReverseSlice() []interface{} {
	sl := s.Slice()
	for i, j := 0, len(sl)-1; i < j; i, j = i+1, j-1 {
		sl[i], sl[j] = sl[j], sl[i]
	}
	return sl
}
