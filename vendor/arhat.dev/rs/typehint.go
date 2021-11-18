package rs

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type TypeHint interface {
	apply(*yaml.Node) (*yaml.Node, error)

	String() string
}

type (
	TypeHintNone    struct{}
	TypeHintStr     struct{}
	TypeHintObject  struct{}
	TypeHintObjects struct{}
	TypeHintInt     struct{}
	TypeHintFloat   struct{}
	TypeHintBool    struct{}
)

func (TypeHintNone) String() string    { return "" }
func (TypeHintStr) String() string     { return "str" }
func (TypeHintObject) String() string  { return "obj" }
func (TypeHintObjects) String() string { return "[]obj" }
func (TypeHintInt) String() string     { return "int" }
func (TypeHintFloat) String() string   { return "float" }
func (TypeHintBool) String() string    { return "bool" }

func (TypeHintNone) apply(v *yaml.Node) (*yaml.Node, error) {
	return prepareYamlNode(v), nil
}

func applyStrHint(n *yaml.Node) (*yaml.Node, error) {
	switch {
	case isStrScalar(n), isBinaryScalar(n):
		return n, nil
	case isBoolScalar(n), isFloatScalar(n), isIntScalar(n):
		// TODO: shall we cast null to string directly?
		return castScalarNode(n, strTag)
	}

	data, err := yaml.Marshal(n)
	if err != nil {
		return nil, err
	}

	return &yaml.Node{
		Style: guessYamlStringStyle(data),
		Kind:  yaml.ScalarNode,
		Tag:   strTag,
		Value: strings.TrimSuffix(string(data), "\n"),
	}, nil
}

func (thi TypeHintStr) apply(n *yaml.Node) (*yaml.Node, error) {
	return applyStrHint(n)
}

func applyObjectHint(n *yaml.Node) (ret *yaml.Node, err error) {
	n = prepareYamlNode(n)
	if isEmpty(n) {
		return nil, nil
	}

	switch n.Kind {
	case yaml.MappingNode:
		return n, nil
	case yaml.ScalarNode:
		// can be string, convert to object
		var dataBytes []byte
		switch {
		case isStrScalar(n):
			dataBytes = []byte(n.Value)
		case isBinaryScalar(n):
			dataBytes, err = base64.StdEncoding.DecodeString(n.Value)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf(
				"unsupported non str nor binary scalar node to object conversion",
			)
		}

		ret = new(yaml.Node)
		defer func() {
			errX := recover()

			if errX != nil {
				err = fmt.Errorf("%v", errX)
			}
		}()
		err = yaml.Unmarshal(dataBytes, ret)
		if err != nil {
			return nil, err
		}

		ret = prepareYamlNode(ret)
		switch {
		case ret == nil,
			ret.Kind == yaml.MappingNode:
			return
		default:
		}

		fallthrough
	default:
		return nil, fmt.Errorf("cannot convert %q to object", n.Kind)
	}
}

func (tho TypeHintObject) apply(n *yaml.Node) (ret *yaml.Node, err error) {
	return applyObjectHint(n)
}

func applyObjectsHint(n *yaml.Node) (ret *yaml.Node, err error) {
	n = prepareYamlNode(n)
	if n == nil || isEmpty(n) {
		return nil, nil
	}

	switch n.Kind {
	case yaml.SequenceNode:
		return n, nil
	case yaml.ScalarNode:
		// can be string, convert to object
		var dataBytes []byte
		switch {
		case isStrScalar(n):
			dataBytes = []byte(n.Value)
		case isBinaryScalar(n):
			dataBytes, err = base64.StdEncoding.DecodeString(n.Value)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf(
				"unsupported non str nor binary scalar node to objects conversion",
			)
		}

		ret = new(yaml.Node)
		defer func() {
			errX := recover()

			if errX != nil {
				err = fmt.Errorf("%v", errX)
			}
		}()

		err = yaml.Unmarshal(dataBytes, ret)
		if err != nil {
			return nil, err
		}

		ret = prepareYamlNode(ret)
		switch {
		case ret == nil,
			ret.Kind == yaml.SequenceNode:
			return
		default:
		}

		fallthrough
	default:
		return nil, fmt.Errorf("cannot convert %q to objects", n.Tag)
	}
}

func (tho TypeHintObjects) apply(n *yaml.Node) (ret *yaml.Node, err error) {
	return applyObjectsHint(n)
}

func (TypeHintFloat) apply(n *yaml.Node) (*yaml.Node, error) {
	return castScalarNode(n, floatTag)
}

func (TypeHintInt) apply(n *yaml.Node) (*yaml.Node, error) {
	return castScalarNode(n, intTag)
}

func (TypeHintBool) apply(n *yaml.Node) (*yaml.Node, error) {
	return castScalarNode(n, boolTag)
}

// cast scalar node directly by changing the tag of it
func castScalarNode(n *yaml.Node, newTag string) (*yaml.Node, error) {
	n = prepareYamlNode(n)
	if n == nil || isEmpty(n) {
		return nil, nil
	}

	if n.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf(
			"unexpected non scalar node for %q", newTag,
		)
	}

	switch {
	case n.Tag == newTag, shortTag(n.Tag) == newTag:
		return n, nil
	}

	ret := cloneYamlNode(n, newTag, n.Value)
	switch newTag {
	case strTag, binaryTag:
	default:
		val, err := strconv.Unquote(n.Value)
		if err != nil {
			// was not quoted
			val = n.Value
		}
		ret.Value = val
	}

	return ret, nil
}

func cloneYamlNode(n *yaml.Node, tag, value string) *yaml.Node {
	return &yaml.Node{
		Kind:        n.Kind,
		Style:       n.Style,
		Tag:         tag,
		Value:       value,
		Anchor:      n.Anchor,
		Alias:       n.Alias,
		Content:     n.Content,
		HeadComment: n.HeadComment,
		LineComment: n.LineComment,
		FootComment: n.FootComment,
		Line:        n.Line,
		Column:      n.Column,
	}
}

var supportedTypeHints = map[string]TypeHint{
	"":      TypeHintNone{},
	"str":   TypeHintStr{},
	"[]obj": TypeHintObjects{},
	"obj":   TypeHintObject{},
	"int":   TypeHintInt{},
	"float": TypeHintFloat{},
	"bool":  TypeHintBool{},
}

func ParseTypeHint(h string) (TypeHint, error) {
	ret, ok := supportedTypeHints[h]
	if !ok {
		return nil, fmt.Errorf("unknown type hint %q", h)
	}

	return ret, nil
}
