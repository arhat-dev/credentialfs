package rs

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML handles parsing of rendering suffix and normal yaml
// unmarshaling
func (f *BaseField) UnmarshalYAML(n *yaml.Node) error {
	if !f.initialized() {
		return fmt.Errorf("rs: struct not intialized before unmarshaling")
	}

	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("rs: unexpected non map data %q for struct %q unmarshaling",
			n.Tag, f._parentType.String(),
		)
	}

	oneLevelMap, err := unmarshalYamlMap(n)
	if err != nil {
		return fmt.Errorf("rs: data unmarshal failed for %s: %w",
			f._parentType.String(), err,
		)
	}

	// set values
	for _, kv := range oneLevelMap {
		rawYamlKey := kv[0].Value

		// custom tag with `!rs:` prefix can also indicate rendering suffix

		var (
			suffixStart = strings.LastIndexByte(rawYamlKey, '@')
			field       = f.getField(rawYamlKey)
			rsTag       = strings.TrimPrefix(strings.TrimPrefix(kv[1].Tag, "!rs:"), "!tag:arhat.dev/rs:")

			yamlKey string
		)
		switch {
		case rsTag != kv[1].Tag:
			// this field is definitely using rendering suffix as
			// indicated by its tag, which can only be set manually
			// in yaml
			//
			// In this case, user MUST NOT set @ style rendering suffix
			// at the same time

			kv[1].Tag = ""
			yamlKey = rawYamlKey
			err = f.unmarshalRS(yamlKey, rsTag, kv)
		case field != nil,
			suffixStart == -1:
			// matched struct field tag `yaml:"foo@http"`
			// or having no rendering suffix
			//
			// this field is definitely not using rendering suffix

			yamlKey = rawYamlKey
			err = f.unmarshalNoRS(yamlKey, kv, field)
		default:
			// suffixStart != -1 (always true)
			// has rendering suffix suffix, and no field tag with exact match

			yamlKey = rawYamlKey[:suffixStart]
			err = f.unmarshalRS(yamlKey, rawYamlKey[suffixStart+1:], kv)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (f *BaseField) unmarshalNoRS(yamlKey string, kv []*yaml.Node, field *fieldRef) error {
	v := kv[1]
	if field == nil {
		field = f.inlineMap
		v = fakeMap(kv[0], kv[1])
	}

	if field == nil {
		if f._opts != nil && f._opts.AllowUnknownFields {
			// allows unknown fields
			return nil
		}

		return fmt.Errorf("rs: unknown yaml field %q to %s",
			yamlKey, f._parentType.String(),
		)
	}

	// field is not nil

	err := unmarshal(nil, yamlKey, v, field, &field.isInlineMap, nil)
	if err != nil {
		return fmt.Errorf("rs: failed to unmarshal yaml field %q to %s.%s: %w",
			yamlKey, f._parentType.String(), field.fieldName, err,
		)
	}

	return nil
}

func (f *BaseField) unmarshalRS(yamlKey, suffix string, kv []*yaml.Node) error {
	field := f.getField(yamlKey)

	v := prepareYamlNode(kv[1])
	if v == nil {
		v = kv[1]
	}
	if field == nil {
		if yamlKey == "__" {
			// handle virtual key
			return f.addUnresolvedField_self(suffix, kv[1])
		}

		v = fakeMap(cloneYamlNode(kv[0], strTag, yamlKey), v)
		field = f.inlineMap
	}

	if field == nil {
		if f._opts != nil && f._opts.AllowUnknownFields {
			return nil
		}

		return fmt.Errorf("rs: unknown yaml field %q to %s",
			yamlKey, f._parentType.String(),
		)
	}

	// field is not nil

	if field.disableRS {
		return fmt.Errorf("rendering suffix is not allowed to %q (%s)",
			yamlKey, f._parentType.String(),
		)
	}

	return field.base.addUnresolvedField(yamlKey, suffix, nil, field, v)
}

// rc is used to resolve virtual key for rendered data (only happening during ResolveFileds)
// so it can be nil when unmarhaling
func unmarshal(
	rc RenderingHandler,
	yamlKey string,
	in *yaml.Node,
	out *fieldRef,
	keepOld *bool,
	// parent of the incoming yaml node, intended to support
	// virtual key `__` for document and sequence item
	//
	// only effective if parent is nil or SequenceNode
	parent *yaml.Node,
) error {
	if !out.fieldValue.IsValid() {
		// no way to know what value we can set
		// NOTE: this should not happen unless user called yaml.Unmarshal with
		// 	     something nil as out
		return fmt.Errorf(
			"invalid nil unmarshal target for yaml key %q",
			yamlKey,
		)
	}

	outKind := out.fieldValue.Kind()

	in = prepareYamlNode(in)
	// reset to zero value if already set
	if isEmpty(in) {
		// only clear out ptr value to keep same behavior as
		// yaml.Unmarshal
		if out.fieldValue.CanSet() {
			switch outKind {
			case reflect.Ptr, reflect.Map, reflect.Slice:
				out.fieldValue.Set(reflect.Zero(out.fieldValue.Type()))
			}
		}
		return nil
	}

	// we are trying to set value of it, so initialize the pointer when not set before
	for outKind == reflect.Ptr {
		if out.fieldValue.IsNil() {
			out.fieldValue.Set(reflect.New(out.fieldValue.Type().Elem()))
		}

		out = out.Elem()
		outKind = out.fieldValue.Kind()
	}

	// handle virtual key `__`
	// resolved value will be treated as incoming node
	if (parent == nil || parent.Kind == yaml.SequenceNode) &&
		in.Kind == yaml.MappingNode {

		pairs, err := unmarshalYamlMap(in)
		if err != nil {
			return fmt.Errorf("invalid mapping node: %w", err)
		}

		// TODO: merge multiple virtual values into one
		var content []*yaml.Node
		for _, pair := range pairs {
			suffix := strings.TrimPrefix(pair[0].Value, "__@")

			if suffix == pair[0].Value {
				content = append(content, pair...)
				continue
			}

			_, err := handleUnresolvedField(rc, 1, out.fieldName,
				&unresolvedFieldSpec{
					ref:       out,
					rawData:   pair[1],
					renderers: parseRenderingSuffix(suffix),
				},
				nil, false,
			)
			if err != nil {
				return err
			}
		}

		in.Content = content
	}

	switch outKind {
	case reflect.Invalid:
		// TODO: this should not happen since we have already checked outVal.IsValid before

		// unreachable code
		return fmt.Errorf("unexpected nil out value for yaml key %q", yamlKey)
	case reflect.Chan, reflect.Func:
		return fmt.Errorf("invalid out value is not data type for yaml key %q", yamlKey)
	case reflect.Array:
		return unmarshalArray(rc, yamlKey, in, out)
	case reflect.Slice:
		return unmarshalSlice(rc, yamlKey, in, out, keepOld)
	case reflect.Map:
		_, err := unmarshalMap(rc, yamlKey, in, out, nil, keepOld)
		return err
	case reflect.Struct:
		return unmarshalStruct(yamlKey, in, out)
	case reflect.Interface:
		handled, err := unmarshalInterface(rc, yamlKey, in, out, keepOld)
		if !handled {
			// fallback to go-yaml behavior
			return in.Decode(out.fieldValue.Addr().Interface())
		}

		return err
	default:
		return in.Decode(out.fieldValue.Addr().Interface())
	}
}

func unmarshalStruct(
	yamlKey string,
	in *yaml.Node,
	outVal *fieldRef,
) error {
	tryInit(outVal.fieldValue, outVal.base._opts)

	var (
		err error
		out = outVal.fieldValue.Addr().Interface()
	)

	switch ot := out.(type) {
	case yaml.Unmarshaler:
		err = ot.UnmarshalYAML(in)
	default:
		err = in.Decode(ot)
	}
	if in.Kind == yaml.MappingNode {
		return err
	}

	if isEmpty(in) {
		return nil
	}

	in, err = TypeHintNone{}.apply(in)
	if err != nil {
		return fmt.Errorf(
			"unexpected input for struct %q %s: %w",
			yamlKey, outVal.fieldValue.Type().String(), err,
		)
	}

	switch ot := out.(type) {
	case yaml.Unmarshaler:
		return ot.UnmarshalYAML(in)
	default:
		return in.Decode(ot)
	}
}

// unmarshalInterface handles interface type creation
func unmarshalInterface(
	rc RenderingHandler,
	yamlKey string,
	in *yaml.Node,
	out *fieldRef,
	keepOld *bool,
) (bool, error) {
	opts := out.base._opts
	if opts == nil || opts.InterfaceTypeHandler == nil {
		// there is no interface type handler
		// use default behavior for interface{} types
		return false, nil
	}

	fVal, err := opts.InterfaceTypeHandler.Create(out.fieldValue.Type(), yamlKey)
	if err != nil {
		if errors.Is(err, ErrInterfaceTypeNotHandled) && out.fieldValue.Type() == rawInterfaceType {
			// no type information provided, decode using go-yaml directly
			return false, nil
		}

		return true, fmt.Errorf(
			"failed to create interface field: %w",
			err,
		)
	}

	val := reflect.ValueOf(fVal)

	if err := checkAssignable(yamlKey, val, out.fieldValue); err != nil {
		return true, err
	}

	if out.fieldValue.CanSet() {
		out.fieldValue.Set(val)
	} else {
		out.fieldValue.Elem().Set(val)
	}

	// DO NOT use outVal directly, which will always match reflect.Interface
	return true, unmarshal(rc, yamlKey, in, out.clone(val), keepOld, in)
}

func unmarshalArray(
	rc RenderingHandler,
	yamlKey string,
	in *yaml.Node,
	out *fieldRef,
) error {
	if in.Kind != yaml.SequenceNode {
		var err error
		in, err = applyObjectsHint(in)
		if err != nil {
			return fmt.Errorf(
				"unexpected input for array %q (%s): %w",
				yamlKey, out.fieldValue.Type().String(), err,
			)
		}
	}

	size := len(in.Content)
	expectedSize := out.fieldValue.Len()
	if size < expectedSize {
		return fmt.Errorf(
			"array size not match for %s: want %d got %d",
			out.fieldValue.Type().String(), expectedSize, size,
		)
	}

	for i := 0; i < expectedSize; i++ {
		err := unmarshal(rc,
			yamlKey, in.Content[i], out.clone(out.fieldValue.Index(i)),
			// always drop existing inner data
			// (actually doesn't matter since it's new)
			nil, in,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to unmarshal #%d array item of yaml field %q for %s: %w",
				i, yamlKey, out.fieldValue.Type().String(), err,
			)
		}
	}

	return nil
}

func unmarshalSlice(
	rc RenderingHandler,
	yamlKey string,
	in *yaml.Node,
	outVal *fieldRef,
	keepOld *bool,
) error {
	if in.Kind != yaml.SequenceNode {
		if isEmpty(in) {
			return nil
		}

		var err error
		in, err = applyObjectsHint(in)
		if err != nil {
			return fmt.Errorf(
				"unexpected input for slice %q (%s): %w",
				yamlKey, outVal.fieldValue.Type().String(), err,
			)
		}
	}

	size := len(in.Content)
	tmpVal := reflect.MakeSlice(outVal.fieldValue.Type(), size, size)

	for i := 0; i < size; i++ {
		err := unmarshal(rc,
			yamlKey, in.Content[i], outVal.clone(tmpVal.Index(i)),
			// always drop existing inner data
			// (actually doesn't matter since it's new)
			nil, in,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to unmarshal #%d slice item of yaml field %q for %s: %w",
				i, yamlKey, outVal.fieldValue.Type().String(), err,
			)
		}
	}

	if err := checkAssignable(yamlKey, tmpVal, outVal.fieldValue); err != nil {
		return err
	}

	if outVal.fieldValue.IsZero() || keepOld == nil || !*keepOld {
		outVal.fieldValue.Set(tmpVal)
	} else {
		outVal.fieldValue.Set(reflect.AppendSlice(outVal.fieldValue, tmpVal))
	}

	return nil
}

// map key MUST be string
// the return value is only meaningful when keepOld is set (resolving inline map pair)
func unmarshalMap(
	rc RenderingHandler,
	yamlKey string,
	in *yaml.Node,
	outVal *fieldRef,
	inlineMapItemCache *reflect.Value,
	keepOld *bool,
) (ret *reflect.Value, _ error) {
	if in.Kind != yaml.MappingNode {
		var err error
		in, err = applyObjectHint(in)
		if err != nil {
			return nil, fmt.Errorf(
				"unexpected input for map %q (%s): %w",
				yamlKey, outVal.fieldValue.Type().String(), err,
			)
		}
	}

	// keepOld can only be set when resolving inline map items
	// then the `in` arg only contain a pair of key value
	//
	// when keepOld is set, there can be some data already unmarshaled
	// inside the map, so we should not create a new map in that case
	if outVal.fieldValue.IsNil() || keepOld == nil {
		outVal.fieldValue.Set(reflect.MakeMap(outVal.fieldValue.Type()))
	}

	m, err := unmarshalYamlMap(in)
	if err != nil {
		return nil, err
	}

	valType := outVal.fieldValue.Type().Elem()
	for i, kv := range m {
		if i == 0 && keepOld != nil && *keepOld && inlineMapItemCache != nil {
			ret = inlineMapItemCache
		} else {
			val := reflect.New(valType).Elem()
			ret = &val
		}

		k := kv[0].Value
		err := unmarshal(
			rc,
			// use k rather than `yamlKey`
			k,
			kv[1], outVal.clone(*ret), keepOld, in,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal map value %s for key %q: %w",
				valType.String(), k, err,
			)
		}

		outVal.fieldValue.SetMapIndex(reflect.ValueOf(k), *ret)
	}

	return ret, nil
}

func checkAssignable(yamlKey string, in, out reflect.Value) error {
	if !in.Type().AssignableTo(out.Type()) {
		return fmt.Errorf(
			"unexpected value of yaml field %q: want %q, got %q",
			yamlKey, out.Type().String(), in.Type().String(),
		)
	}

	return nil
}
