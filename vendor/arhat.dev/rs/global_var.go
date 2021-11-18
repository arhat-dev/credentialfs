package rs

import "reflect"

var (
	stringType = reflect.TypeOf("")

	baseFieldPtrType    = reflect.TypeOf((*BaseField)(nil))
	baseFieldStructType = baseFieldPtrType.Elem()

	fieldInterfaceType = reflect.TypeOf((*Field)(nil)).Elem()
	rawInterfaceType   = reflect.TypeOf((*interface{})(nil)).Elem()
)
