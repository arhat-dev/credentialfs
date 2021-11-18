//go:build !rs_noyamlmarshaler
// +build !rs_noyamlmarshaler

package rs

import (
	"fmt"
	"reflect"
)

// MarshalYAML implements yaml.Marshaler by making a map of all fields
// known to BaseField
//
// You can opt-out with build tag `rs_noyamlmarshaler`
func (f *BaseField) MarshalYAML() (interface{}, error) {
	if !f.initialized() {
		return nil, fmt.Errorf("rs: struct not intialized before marshaling")
	}

	ret := make(map[string]interface{})

	// handle catch other fields first, so they can be overridden
	// by normal fields
	if f.inlineMap != nil && f.inlineMap.fieldValue.IsValid() {
		// NOTE: we MUST not use catch other cache since user can
		// 		 access map directly without updating our cache
		iter := f.inlineMap.fieldValue.MapRange()
		for iter.Next() {
			// always include it no matter what value it has
			//
			// if not, unmarshal using our output will give
			// different result
			k, v := iter.Key().String(), iter.Value()

			if v.Kind() == reflect.Ptr && v.IsNil() {
				ret[k] = nil
				continue
			}

			ret[k] = v.Interface()
		}
	}

	for k, v := range f.normalFields {
		vk := v.fieldValue.Kind()

		if v.omitempty {
			if !v.fieldValue.IsValid() || (vk != reflect.Array && v.fieldValue.IsZero()) {
				// value not set or zero value, just ignore it
				continue
			}

			// value already set and not zero value
			switch vk {
			case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
				if v.fieldValue.Len() == 0 {
					continue
				}
			}
		}

		if vk == reflect.Ptr && v.fieldValue.IsNil() {
			ret[k] = nil
			continue
		}

		ret[k] = v.fieldValue.Interface()
	}

	return ret, nil
}
