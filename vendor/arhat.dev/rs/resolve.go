package rs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"gopkg.in/yaml.v3"
)

func (f *BaseField) HasUnresolvedField() bool {
	return len(f.unresolvedNormalFields) != 0
}

func (f *BaseField) ResolveFields(rc RenderingHandler, depth int, names ...string) error {
	if !f.initialized() {
		return fmt.Errorf("rs: struct not intialized before resolving")
	}

	if depth == 0 {
		return nil
	}

	if len(names) == 0 {
		// resolve all

		err := resolveOverlappedItems(rc, 1, "", f.unresolvedSelfItems, f._parentValue)
		if err != nil {
			return err
		}

		for name, v := range f.normalFields {
			err := v.base.resolveNormalField(rc, depth, name, v)
			if err != nil {
				return fmt.Errorf(
					"rs: failed to resolve field %s.%s: %w",
					f._parentType.String(), v.fieldName, err,
				)
			}
		}

		for k, list := range f.unresolvedInlineMapItems {
			err := resolveOverlappedItems(rc, depth, k, list, f.inlineMap.fieldValue)
			if err != nil {
				return err
			}
		}

		if f.inlineMap != nil {
			// the inline map haves been resolved above, so let's go to
			// values of these inline map entries
			return handleResolvedField(rc, depth, f.inlineMap.fieldValue)
		}

		return nil
	}

	for _, name := range names {
		v, ok := f.normalFields[name]
		if !ok {
			// can be targeting inline map field name
			switch {
			case len(name) == 0:
				// resolve itself (added by virtual key `__`)

				err := resolveOverlappedItems(rc, 1, "", f.unresolvedSelfItems, f._parentValue)
				if err != nil {
					return err
				}

				continue
			case f.inlineMap != nil && f.inlineMap.fieldName == name:
				for k, list := range f.unresolvedInlineMapItems {
					err := resolveOverlappedItems(rc, depth, k, list, f.inlineMap.fieldValue)
					if err != nil {
						return err
					}
				}

				continue
			default:
				return fmt.Errorf(
					"rs: no such field %q in struct %q",
					name, f._parentType.String(),
				)
			}
		}

		err := v.base.resolveNormalField(rc, depth, name, v)
		if err != nil {
			return fmt.Errorf(
				"rs: failed to resolve requested field %s of %s: %w",
				name, f._parentType.String(), err,
			)
		}
	}

	return nil
}

func resolveOverlappedItems(
	rc RenderingHandler,
	depth int,
	k string,
	list []*unresolvedFieldSpec,
	fVal reflect.Value,
) error {
	var (
		itemCache *reflect.Value
		err       error
	)

	for i, v := range list {
		itemCache, err = handleUnresolvedField(
			rc, depth, k, v, itemCache,
			// flush existing data with the same key on first pair
			i != 0,
		)
		if err != nil {
			return err
		}
	}

	return handleResolvedField(rc, depth, fVal)
}

func (f *BaseField) resolveNormalField(
	rc RenderingHandler,
	depth int,
	yamlKey string,
	targetField *fieldRef,
) error {
	v, ok := f.unresolvedNormalFields[yamlKey]
	if !ok {
		return handleResolvedField(rc, depth, targetField.fieldValue)
	}

	_, err := handleUnresolvedField(
		rc, depth, yamlKey, v, nil, false,
	)
	return err
}

func handleResolvedField(
	rc RenderingHandler,
	depth int,
	field reflect.Value,
) error {
	if depth == 0 {
		return nil
	}

	switch fk := field.Kind(); fk {
	case reflect.Map:
		if field.IsNil() {
			return nil
		}

		iter := field.MapRange()
		for iter.Next() {
			err := handleResolvedField(rc, depth-1, iter.Value())
			if err != nil {
				return err
			}
		}
	case reflect.Array:
		fallthrough
	case reflect.Slice:
		if fk == reflect.Slice && field.IsNil() {
			// this is a resolved field, slice/array empty means no value
			return nil
		}

		for i := 0; i < field.Len(); i++ {
			tt := field.Index(i)
			err := handleResolvedField(rc, depth-1, tt)
			if err != nil {
				return err
			}
		}
	case reflect.Struct:
		// handled after switch
	case reflect.Ptr:
		fallthrough
	case reflect.Interface:
		if !field.IsValid() || field.IsZero() || field.IsNil() {
			return nil
		}
		// handled after switch
	default:
		// scalar types, no action required
		return nil
	}

	return tryResolve(rc, depth-1, field)
}

func tryResolve(rc RenderingHandler, depth int, targetField reflect.Value) error {
	if targetField.CanInterface() {
		fVal, canCallResolve := targetField.Interface().(Field)
		if canCallResolve {
			// fVal can have underlying data nil, but with Field type
			if targetField.IsNil() {
				return nil
			}

			return fVal.ResolveFields(rc, depth)
		}
	}

	if !targetField.CanAddr() {
		return nil
	}

	targetField = targetField.Addr()
	if !targetField.CanInterface() {
		return nil
	}

	fVal, canCallResolve := targetField.Interface().(Field)
	if canCallResolve {
		if targetField.IsNil() {
			return nil
		}

		return fVal.ResolveFields(rc, depth)
	}

	// no more field to resolve
	return nil
}

func handleUnresolvedField(
	rc RenderingHandler,
	depth int,
	yamlKey string,
	v *unresolvedFieldSpec,
	inlineMapItemCache *reflect.Value,
	keepOld bool,
) (*reflect.Value, error) {
	target := v.ref

	toResolve := v.rawData
	if v.ref.isInlineMap {
		// unwrap map data for resolving
		toResolve = v.rawData.Content[1]
	}

	var err error
	for _, renderer := range v.renderers {
		toResolve, err = tryRender(rc,
			renderer.name, renderer.typeHint, renderer.patchSpec,
			toResolve,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to render value for %q: %w", yamlKey, err)
		}
	}

	resolved := toResolve
	if v.ref.isInlineMap {
		inlineMapItemCache, err = unmarshalMap(
			rc,
			yamlKey,
			fakeMap(v.rawData.Content[0], resolved),
			target,
			inlineMapItemCache,
			&keepOld,
		)
	} else {
		err = unmarshal(rc, yamlKey, resolved, target, nil, nil)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"failed to unmarshal resolved value of %q to field %q: %w",
			yamlKey, target.fieldName, err,
		)
	}

	return inlineMapItemCache, handleResolvedField(rc, depth, target.fieldValue)
}

func tryRender(
	rc RenderingHandler,
	rendererName string,
	typeHint TypeHint,
	isPatchSpec bool,
	toResolve *yaml.Node,
) (*yaml.Node, error) {
	if isPatchSpec {
		patchSpec, err := resolvePatchSpec(rc, toResolve)
		if err != nil {
			return nil, fmt.Errorf("invalid patch spec: %w", err)
		}

		patchedData, err := patchSpec.Apply(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to apply patch: %w", err)
		}

		// patch doc is generated from arbitrary yaml data
		// with built-in interface{}, so we are able to marshal it into
		// json, and parse as *yaml.Node for further processing

		var dataBytes []byte
		dataBytes, err = json.Marshal(patchedData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal patched data: %w", err)
		}

		// json data is deemed to be valid yaml, if not, we must have some
		// big problem. so we don't need to recover yaml.Unmarshal from panic
		// here
		toResolve = new(yaml.Node)
		err = yaml.Unmarshal(dataBytes, toResolve)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare patched data: %w", err)
		}
	}

	if len(rendererName) != 0 {
		renderedData, err := rc.RenderYaml(rendererName, toResolve)
		if err != nil {
			return nil, fmt.Errorf(
				"renderer %q failed to render value: %w",
				rendererName, err,
			)
		}

		// check type hinting before assuming it's valid yaml
		//
		// see TestResolve_yaml_unmarshal_invalid_but_no_error in resolve_test.go
		// for reasons this pre-type hint check exists

		// scalar types cannot be applied with patch spec
		// so the rendered data will be the final value for resolving

		var tag string
		switch typeHint.(type) {
		case TypeHintStr:
			tag = strTag
		case TypeHintInt:
			tag = intTag
		case TypeHintFloat:
			tag = floatTag
		default:
			// assume rendered data as yaml for further processing
			toResolve = assumeValidYaml(renderedData)
		}

		if len(tag) != 0 {
			toResolve = &yaml.Node{
				Style: guessYamlStringStyle(renderedData),
				Kind:  yaml.ScalarNode,
				Tag:   tag,
				Value: string(renderedData),
			}
		}
	}

	// apply hint after resolving (rendering)
	toResolve, err := applyHint(typeHint, toResolve)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure type hint %q: %w", typeHint, err)
	}

	return toResolve, nil
}

func guessYamlStringStyle(s []byte) yaml.Style {
	switch {
	case bytes.IndexByte(s, '\n') != -1:
		return yaml.LiteralStyle
	default:
		return 0
	}
}

// assumeValidYaml tries its best to unmarshal data as yaml.Node
func assumeValidYaml(data []byte) (ret *yaml.Node) {
	defer func() {
		// TODO: yaml.Unmarshal can panic on invalid but seemingly
		// 		 correct input (e.g. markdown)
		//
		// related upstream issue:
		// 	https://github.com/go-yaml/yaml/issues/665
		errX := recover()

		if errX != nil {
			ret = &yaml.Node{
				Style: guessYamlStringStyle(data),
				Kind:  yaml.ScalarNode,
				Tag:   strTag,
				Value: string(data),
			}
		}
	}()

	ret = new(yaml.Node)
	err := yaml.Unmarshal(data, ret)
	if err != nil {
		ret = &yaml.Node{
			Style: guessYamlStringStyle(data),
			Kind:  yaml.ScalarNode,
			Tag:   strTag,
			Value: string(data),
		}

		return
	}

	// unmarshal ok
	if prepared := prepareYamlNode(ret); prepared != nil {
		ret = prepared
	}

	switch {
	case isStrScalar(ret), isBinaryScalar(ret):
		// use original string instead of yaml unmarshaled string
		// yaml.Unmarshal may modify string content when it's not
		// valid yaml

		ret = &yaml.Node{
			Style: guessYamlStringStyle(data),
			Kind:  yaml.ScalarNode,
			Tag:   strTag,
			Value: string(data),
		}
	}

	return
}

// applyHint applies type hint to yaml.Node, default to TypeHintNone if hint is nil
// return value is set to input if the hinted result is nil
func applyHint(hint TypeHint, in *yaml.Node) (*yaml.Node, error) {
	if hint == nil {
		hint = TypeHintNone{}
	}

	// hintedToResolve can be nil
	hintedToResolve, err := hint.apply(in)
	if err != nil {
		return in, err
	}

	if hintedToResolve != nil {
		return hintedToResolve, nil
	}

	return in, nil
}

// resolve user provided data as patch spec
func resolvePatchSpec(
	rc RenderingHandler, toResolve *yaml.Node,
) (patchSpec *PatchSpec, err error) {
	patchSpec = Init(&PatchSpec{}, nil).(*PatchSpec)
	err = toResolve.Decode(patchSpec)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to decode patch spec: %w",
			err,
		)
	}

	err = patchSpec.ResolveFields(rc, -1)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve patch spec: %w",
			err,
		)
	}

	return patchSpec, err
}

func handleOptionalRenderingSuffixResolving(rc RenderingHandler, n *yaml.Node, resolve *bool) (interface{}, error) {
	n = prepareYamlNode(n)
	if n == nil {
		return nil, nil
	}

	if resolve == nil || *resolve {
		any := new(AnyObject)
		err := n.Decode(any)
		if err != nil {
			return nil, err
		}

		err = any.ResolveFields(rc, -1)
		if err != nil {
			return nil, err
		}

		return any.NormalizedValue(), nil
	}

	var ret interface{}
	err := n.Decode(&ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
}
