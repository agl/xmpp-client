package xlib

import (
	"strings"
)

type priorityListEntry struct {
	value string
	next  *priorityListEntry
}

type PriorityList struct {
	head       *priorityListEntry
	lastPrefix string
	lastResult string
	n          int
}

func (pl *PriorityList) Insert(value string) {
	ent := new(priorityListEntry)
	ent.next = pl.head
	ent.value = value
	pl.head = ent
}

func (pl *PriorityList) findNth(prefix string, nth int) (string, bool) {
	var cur, last *priorityListEntry
	cur = pl.head
	for n := 0; cur != nil; cur = cur.next {
		if strings.HasPrefix(cur.value, prefix) {
			if n == nth {
				// move this entry to the top
				if last != nil {
					last.next = cur.next
				} else {
					pl.head = cur.next
				}
				cur.next = pl.head
				pl.head = cur
				pl.lastResult = cur.value
				return cur.value, true
			}
			n++
		}
		last = cur
	}

	return "", false
}

func (pl *PriorityList) Find(prefix string) (string, bool) {
	pl.lastPrefix = prefix
	pl.n = 0

	return pl.findNth(prefix, 0)
}

func (pl *PriorityList) Next() string {
	pl.n++
	result, ok := pl.findNth(pl.lastPrefix, pl.n)
	if !ok {
		pl.n = 1
		result, ok = pl.findNth(pl.lastPrefix, pl.n)
	}
	// In this case, there's only one matching entry in the list.
	if !ok {
		pl.n = 0
		result, _ = pl.findNth(pl.lastPrefix, pl.n)
	}
	return result
}
