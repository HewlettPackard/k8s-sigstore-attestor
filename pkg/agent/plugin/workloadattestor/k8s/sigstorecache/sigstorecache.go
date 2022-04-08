package sigstorecache

import (
	"container/list"

	"github.com/sigstore/cosign/pkg/oci"
)

// Item represents a key-value pair
type Item struct {
	Key   string
	Value []oci.Signature
}

// Cache defines the behaviors of our cache
type Cache interface {
	GetSignature(key string) *Item
	PutSignature(Item)
}

// cache implements Cache interface
type Cacheimpl struct {
	size  int
	items *list.List
}

// NewCache creates and returns a new cache
func NewCache(maximumAmountCache int) Cache {
	return &Cacheimpl{
		size:  maximumAmountCache,
		items: list.New(),
	}
}

// Get returns an existing item from the cache.
// Get also moves the existing item to the front of the items list to indicate that the existing item is recently used.
func (c *Cacheimpl) GetSignature(key string) *Item {
	e := c.getElement(key)
	if e == nil {
		return nil
	}

	c.items.MoveToFront(e)

	i := e.Value.(Item)

	return &i
}

// Put puts a new item into the cache.
// Put removes the least recently used item from the items list when the cache is full.
// Put pushes the new item to the front of the items list to indicate that the new item is recently used.
func (c *Cacheimpl) PutSignature(i Item) {
	e := c.getElement(i.Key)
	if e != nil {
		c.items.MoveToFront(e)
		return
	}

	if c.items.Len() == c.size {
		c.items.Remove(c.items.Back())
	}

	c.items.PushFront(i)
}

// getElement returns list element of an existing item
func (c *Cacheimpl) getElement(key string) *list.Element {
	for e := c.items.Front(); e != nil; e = e.Next() {
		i := e.Value.(Item)
		if i.Key == key {
			return e
		}
	}

	return nil
}
