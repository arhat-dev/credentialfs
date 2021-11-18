package rs

import (
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	nullTag      = "!!null"
	boolTag      = "!!bool"
	strTag       = "!!str"
	intTag       = "!!int"
	floatTag     = "!!float"
	timestampTag = "!!timestamp"
	seqTag       = "!!seq"
	mapTag       = "!!map"
	binaryTag    = "!!binary"
	mergeTag     = "!!merge"
)

var longTags = make(map[string]string)
var shortTags = make(map[string]string)

func init() {
	for _, stag := range []string{
		nullTag, boolTag, strTag, intTag, floatTag,
		timestampTag, seqTag, mapTag, binaryTag, mergeTag,
	} {
		ltag := longTag(stag)
		longTags[stag] = ltag
		shortTags[ltag] = stag
	}
}

const longTagPrefix = "tag:yaml.org,2002:"

func shortTag(tag string) string {
	if strings.HasPrefix(tag, longTagPrefix) {
		if stag, ok := shortTags[tag]; ok {
			return stag
		}
		return "!!" + tag[len(longTagPrefix):]
	}
	return tag
}

func longTag(tag string) string {
	if strings.HasPrefix(tag, "!!") {
		if ltag, ok := longTags[tag]; ok {
			return ltag
		}
		return longTagPrefix + tag[2:]
	}
	return tag
}

func isMerge(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode &&
		n.Value == "<<" &&
		(n.Tag == "" || n.Tag == "!" || shortTag(n.Tag) == mergeTag)
}

func isEmpty(n *yaml.Node) bool {
	for n != nil {
		switch n.Kind {
		case 0:
			// node not initialized
			return true
		case yaml.DocumentNode:
			switch len(n.Content) {
			case 0:
				return true
			case 1:
				n = n.Content[0]
			default:
				return false
			}
		case yaml.ScalarNode:
			return isNullScalar(n)
		default:
			return false
		}
	}

	return n == nil
}

func checkScalarType(n *yaml.Node, expectedTag string) bool {
	if n.Kind != yaml.ScalarNode {
		return false
	}

	if len(n.Value) == 0 && len(n.Tag) == 0 {
		n.Tag = nullTag
		return n.Tag == expectedTag
	}

	if len(n.Tag) == 0 || n.Tag == "!" {
		n.Tag = n.ShortTag()
		if len(n.Tag) != 0 {
			return n.Tag == expectedTag
		}

		// n.SchortTag may not generate valid tag value when value is not set
		if len(n.Tag) == 0 || n.Tag == "!" {
			n.Tag = nullTag
			return n.Tag == expectedTag
		}
	}

	return shortTag(n.Tag) == expectedTag
}

func isIntScalar(n *yaml.Node) bool    { return checkScalarType(n, intTag) }
func isFloatScalar(n *yaml.Node) bool  { return checkScalarType(n, floatTag) }
func isBoolScalar(n *yaml.Node) bool   { return checkScalarType(n, boolTag) }
func isNullScalar(n *yaml.Node) bool   { return checkScalarType(n, nullTag) }
func isBinaryScalar(n *yaml.Node) bool { return checkScalarType(n, binaryTag) }
func isStrScalar(n *yaml.Node) bool    { return checkScalarType(n, strTag) }
