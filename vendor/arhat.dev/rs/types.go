package rs

import (
	"encoding/base64"
	"reflect"

	"gopkg.in/yaml.v3"
)

// Struct field tag names used by this package
const (
	TagNameRS = "rs"
	TagName   = TagNameRS
)

// Field defines methods required for rendering suffix support
//
// these methods are implemented by BaseField, so usually you should just embed
// BaseField in your struct as the very first field
type Field interface {
	// A Field must implement yaml.Unmarshaler interface to process rendering suffix
	// in yaml key
	yaml.Unmarshaler

	// ResolveFields sets struct field values with data from unmarshaled yaml
	//
	// depth controls to what level this function call goes
	// when depth >= 1, resolve inner fields until reaching depth limit (depth == 0)
	// when depth == 0, do nothing
	// when depth < 0, resolve recursively
	//
	// names limits which fields to be resolved, their values are derived from
	// your field tags
	// When it's not empty, resolve specified fields only, otherwise, resolve all exported fields
	// in the struct.
	ResolveFields(rc RenderingHandler, depth int, names ...string) error
}

type (
	// RenderingHandler is used when resolving yaml fields
	RenderingHandler interface {
		// RenderYaml transforms rawData to result through the renderer
		//
		// renderer is the name of your renderer without type hint (`?<hint>`) and patch suffix (`!`)
		//
		// rawData is the input to your renderer, which can have one of following types
		// - golang primitive types (e.g. int, float32)
		// - map[string]interface{}
		// - []interface{}
		// - *yaml.Node
		// when it's not *yaml.Node type, it was patched by built-in data patching support
		// (as indicated by the `!` suffix to your renderer)
		//
		// Your renderer is responsible for casting it to its desired data type
		RenderYaml(renderer string, rawData interface{}) (result []byte, err error)
	}

	// RenderingHandleFunc is a helper type to wrap your function as RenderingHandler
	RenderingHandleFunc func(renderer string, rawData interface{}) (result []byte, err error)
)

func (f RenderingHandleFunc) RenderYaml(renderer string, rawData interface{}) (result []byte, err error) {
	return f(renderer, rawData)
}

type (
	// InterfaceTypeHandler is used when setting values for interface{} typed field
	InterfaceTypeHandler interface {
		// Create request interface type using yaml information
		Create(typ reflect.Type, yamlKey string) (interface{}, error)
	}

	// InterfaceTypeHandleFunc is a helper type to wrap your function as InterfaceTypeHandler
	InterfaceTypeHandleFunc func(typ reflect.Type, yamlKey string) (interface{}, error)
)

func (f InterfaceTypeHandleFunc) Create(typ reflect.Type, yamlKey string) (interface{}, error) {
	return f(typ, yamlKey)
}

func NormalizeRawData(rawData interface{}) (interface{}, error) {
	if n, ok := rawData.(*yaml.Node); ok && n != nil {
		if isStrScalar(n) {
			return n.Value, nil
		}

		switch n.ShortTag() {
		case nullTag:
			return nil, nil
		case binaryTag:
			return base64.StdEncoding.DecodeString(n.Value)
		}

		var data interface{}
		err := n.Decode(&data)
		if err != nil {
			return nil, err
		}

		return data, nil
	}

	return rawData, nil
}
