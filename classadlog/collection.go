package classadlog

import (
	"fmt"
	"sync"

	"github.com/PelicanPlatform/classad/classad"
)

// Collection stores ClassAds in memory with thread-safe access
type Collection struct {
	ads map[string]*classad.ClassAd
	mu  sync.RWMutex
}

// NewCollection creates a new ClassAd collection
func NewCollection() *Collection {
	return &Collection{
		ads: make(map[string]*classad.ClassAd),
	}
}

// Reset clears all ClassAds from the collection
func (c *Collection) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ads = make(map[string]*classad.ClassAd)
}

// NewClassAd creates a new ClassAd with the given key
func (c *Collection) NewClassAd(key, myType, targetType string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create new ClassAd
	ad := classad.New()

	// Set MyType if provided
	if myType != "" {
		_ = ad.Set("MyType", myType)
	}

	// Set TargetType if provided
	if targetType != "" {
		_ = ad.Set("TargetType", targetType)
	}

	c.ads[key] = ad
	return nil
}

// DestroyClassAd removes a ClassAd from the collection
func (c *Collection) DestroyClassAd(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.ads, key)
	return nil
}

// SetAttribute sets an attribute on a ClassAd
// Creates the ClassAd if it doesn't exist (handles ordering issues where
// SetAttribute may appear before NewClassAd)
func (c *Collection) SetAttribute(key, name, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get or create ClassAd
	ad, exists := c.ads[key]
	if !exists {
		ad = classad.New()
		c.ads[key] = ad
	}

	// Parse the value as a ClassAd expression
	expr, err := classad.ParseExpr(value)
	if err != nil {
		return fmt.Errorf("failed to parse attribute value %q: %w", value, err)
	}

	// Insert the attribute
	ad.InsertExpr(name, expr)

	return nil
}

// DeleteAttribute removes an attribute from a ClassAd
func (c *Collection) DeleteAttribute(key, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ad, exists := c.ads[key]
	if !exists {
		// Silently ignore if ClassAd doesn't exist
		return nil
	}

	ad.Delete(name)
	return nil
}

// Get returns a copy of a ClassAd by key (thread-safe)
// Returns nil if the ClassAd doesn't exist
func (c *Collection) Get(key string) *classad.ClassAd {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ad, exists := c.ads[key]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modifications
	// We create a new ClassAd and copy all attributes
	copy := classad.New()
	attrs := ad.GetAttributes()
	for _, attrName := range attrs {
		if expr, ok := ad.Lookup(attrName); ok {
			copy.InsertExpr(attrName, expr)
		}
	}
	return copy
}

// Query returns ClassAds matching the constraint
// projection specifies which attributes to include (nil = all)
// Returns copies of matching ClassAds
func (c *Collection) Query(constraint string, projection []string) ([]*classad.ClassAd, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var results []*classad.ClassAd

	// Parse constraint if provided
	var constraintExpr *classad.Expr
	if constraint != "" {
		var err error
		constraintExpr, err = classad.ParseExpr(constraint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse constraint: %w", err)
		}
	}

	// Evaluate constraint against each ClassAd
	for _, ad := range c.ads {
		// Check constraint if provided
		if constraintExpr != nil {
			result := ad.EvaluateAttr(constraintExpr.String())
			if result.IsError() || result.IsUndefined() {
				continue // Constraint evaluation failed or undefined
			}
			matches, err := result.BoolValue()
			if err != nil || !matches {
				continue // Constraint didn't match
			}
		}

		// Apply projection if specified
		var resultAd *classad.ClassAd
		if len(projection) > 0 {
			resultAd = classad.New()
			for _, attrName := range projection {
				if expr, ok := ad.Lookup(attrName); ok {
					resultAd.InsertExpr(attrName, expr)
				}
			}
		} else {
			// No projection, return full ClassAd copy
			resultAd = classad.New()
			attrs := ad.GetAttributes()
			for _, attrName := range attrs {
				if expr, ok := ad.Lookup(attrName); ok {
					resultAd.InsertExpr(attrName, expr)
				}
			}
		}

		results = append(results, resultAd)
	}

	return results, nil
}

// GetAllKeys returns all keys in the collection
func (c *Collection) GetAllKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.ads))
	for key := range c.ads {
		keys = append(keys, key)
	}
	return keys
}

// Len returns the number of ClassAds in the collection
func (c *Collection) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.ads)
}
