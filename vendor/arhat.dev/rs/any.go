package rs

import (
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

// AnyObject is a `interface{}` equivalent with rendering suffix support
type AnyObject struct {
	BaseField `yaml:"-" json:"-"`

	mapData    *AnyObjectMap
	sliceData  []*AnyObject
	scalarData interface{}
}

// NormalizedValue returns underlying value of the AnyObject with primitive types
// that is:
// 	for maps: map[string]interface{}
// 	for slices: []interface{}
//  and primitive types for scalar types
//
// should be called after fields being resolved
func (o *AnyObject) NormalizedValue() interface{} {
	switch {
	case o == nil:
		return nil
	case o.mapData != nil:
		return o.mapData.NormalizedValue()
	case o.sliceData != nil:
		ret := make([]interface{}, len(o.sliceData))
		for i := range o.sliceData {
			ret[i] = o.sliceData[i].NormalizedValue()
		}
		return ret
	default:
		return o.scalarData
	}
}

func (o *AnyObject) value() interface{} {
	switch {
	case o == nil:
		return nil
	case o.mapData != nil:
		return o.mapData
	case o.sliceData != nil:
		return o.sliceData
	default:
		return o.scalarData
	}
}

func (o *AnyObject) MarshalYAML() (interface{}, error) { return o.value(), nil }
func (o *AnyObject) MarshalJSON() ([]byte, error)      { return json.Marshal(o.value()) }

func (o *AnyObject) UnmarshalYAML(n *yaml.Node) error {
	if !o.BaseField.initialized() {
		_ = Init(o, nil)
	}

	switch n.Kind {
	case yaml.SequenceNode:
		o.sliceData = make([]*AnyObject, len(n.Content))
		for i, vn := range n.Content {
			o.sliceData[i] = Init(&AnyObject{}, o._opts).(*AnyObject)
			err := o.sliceData[i].UnmarshalYAML(prepareYamlNode(vn))
			if err != nil {
				return err
			}
		}

		return nil
	case yaml.MappingNode:
		pairs, err := unmarshalYamlMap(n)
		if err != nil {
			return err
		}

		var content []*yaml.Node
		for _, pair := range pairs {
			if suffix := strings.TrimPrefix(pair[0].Value, "__@"); suffix != pair[0].Value {
				// is virtual key
				err := o.BaseField.addUnresolvedField_self(suffix, pair[1])
				if err != nil {
					return err
				}

				continue
			}

			content = append(content, pair...)
		}

		if len(content) == 0 {
			return nil
		}

		n.Content = content
		if o.mapData == nil {
			o.mapData = Init(&AnyObjectMap{}, o._opts).(*AnyObjectMap)
		}

		return n.Decode(o.mapData)
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case strTag:
			o.scalarData = n.Value
		case binaryTag:
			o.scalarData = n.Value
		default:
			return n.Decode(&o.scalarData)
		}
		return nil
	default:
		// unreachable
		return n.Decode(&o.scalarData)
	}
}

func (o *AnyObject) ResolveFields(rc RenderingHandler, depth int, names ...string) error {
	if o == nil {
		return nil
	}

	err := o.BaseField.ResolveFields(rc, depth)
	if err != nil {
		return err
	}

	if o.mapData != nil {
		return o.mapData.ResolveFields(rc, depth, names...)
	}

	if o.sliceData != nil {
		for _, v := range o.sliceData {
			err := v.ResolveFields(rc, depth, names...)
			if err != nil {
				return err
			}
		}

		return nil
	}

	// scalar type data doesn't need resolving
	return nil
}

// AnyObjectMap is a `map[string]interface{}` equivalent with rendering suffix support
type AnyObjectMap struct {
	BaseField `yaml:"-" json:"-"`

	Data map[string]*AnyObject `rs:"other"`
}

// NormalizedValue returns value of the AnyObjectMap with type map[string]interface{}
func (aom *AnyObjectMap) NormalizedValue() map[string]interface{} {
	if aom.Data == nil {
		return nil
	}

	ret := make(map[string]interface{}, len(aom.Data))
	for k, v := range aom.Data {
		ret[k] = v.NormalizedValue()
	}

	return ret
}

func (aom *AnyObjectMap) MarshalYAML() (interface{}, error) { return aom.Data, nil }
func (aom *AnyObjectMap) MarshalJSON() ([]byte, error)      { return json.Marshal(aom.Data) }
