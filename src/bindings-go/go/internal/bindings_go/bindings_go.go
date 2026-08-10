package bindings_go

// #include <bindings_go.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

// C.RustBuffer fields exposed as an interface so they can be accessed in different Go packages.
// See https://github.com/golang/go/issues/13467
type ExternalCRustBuffer interface {
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromC(b C.RustBuffer) ExternalCRustBuffer {
	return GoRustBuffer{
		inner: b,
	}
}

func CFromRustBuffer(b ExternalCRustBuffer) C.RustBuffer {
	return C.RustBuffer{
		capacity: C.uint64_t(b.Capacity()),
		len:      C.uint64_t(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func RustBufferFromExternal(b ExternalCRustBuffer) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_bindings_go_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_bindings_go_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter BufReader[E], callback func(*C.RustCallStatus) U) (U, E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[E], status C.RustCallStatus) E {
	switch status.code {
	case 0:
		var zero E
		return zero
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 30
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_bindings_go_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("bindings_go: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_func_version()
		})
		if checksum != 34153 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_func_version: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gocelengine_engine_name()
		})
		if checksum != 569 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gocelengine_engine_name: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gocelengine_list_rules_json()
		})
		if checksum != 41802 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gocelengine_list_rules_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gocelengine_validate_detailed_json()
		})
		if checksum != 26703 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gocelengine_validate_detailed_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gocelengine_validate_standard_json()
		})
		if checksum != 38180 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gocelengine_validate_standard_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_goregoengine_engine_name()
		})
		if checksum != 2132 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_goregoengine_engine_name: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_goregoengine_list_rules_json()
		})
		if checksum != 21491 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_goregoengine_list_rules_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_goregoengine_validate_detailed_json()
		})
		if checksum != 30076 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_goregoengine_validate_detailed_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_goregoengine_validate_standard_json()
		})
		if checksum != 60446 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_goregoengine_validate_standard_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_goschemavalidator_list_rules_json()
		})
		if checksum != 34783 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_goschemavalidator_list_rules_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_goschemavalidator_schema_count()
		})
		if checksum != 53053 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_goschemavalidator_schema_count: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_goschemavalidator_validate_json()
		})
		if checksum != 33987 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_goschemavalidator_validate_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_conditions()
		})
		if checksum != 43827 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_conditions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_description()
		})
		if checksum != 42604 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_description: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_format_version()
		})
		if checksum != 44925 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_format_version: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_outputs_json()
		})
		if checksum != 21852 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_outputs_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_parameters_json()
		})
		if checksum != 40631 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_parameters_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_resources_json()
		})
		if checksum != 55570 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_resources_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_source_location_json()
		})
		if checksum != 27662 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_source_location_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_to_diagnostic_model_json()
		})
		if checksum != 27194 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_to_diagnostic_model_json: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_method_gosemanticmodel_transforms()
		})
		if checksum != 42597 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_method_gosemanticmodel_transforms: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_constructor_gocelengine_new()
		})
		if checksum != 62326 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_constructor_gocelengine_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_constructor_goregoengine_new()
		})
		if checksum != 50221 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_constructor_goregoengine_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_constructor_goschemavalidator_new()
		})
		if checksum != 22024 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_constructor_goschemavalidator_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_bindings_go_checksum_constructor_gosemanticmodel_parse()
		})
		if checksum != 26361 {
			// If this happens try cleaning and rebuilding your project
			panic("bindings_go: uniffi_bindings_go_checksum_constructor_gosemanticmodel_parse: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (c FfiConverterString) LowerExternal(value string) ExternalCRustBuffer {
	return RustBufferFromC(stringToRustBuffer(value))
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) C.RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) LowerExternal(value []byte) ExternalCRustBuffer {
	return RustBufferFromC(c.Lower(value))
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct{}

func (FfiDestroyerBytes) Destroy(_ []byte) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	handle        C.uint64_t
	callCounter   atomic.Int64
	cloneFunction func(C.uint64_t, *C.RustCallStatus) C.uint64_t
	freeFunction  func(C.uint64_t, *C.RustCallStatus)
	destroyed     atomic.Bool
}

func newFfiObject(
	handle C.uint64_t,
	cloneFunction func(C.uint64_t, *C.RustCallStatus) C.uint64_t,
	freeFunction func(C.uint64_t, *C.RustCallStatus),
) FfiObject {
	return FfiObject{
		handle:        handle,
		cloneFunction: cloneFunction,
		freeFunction:  freeFunction,
	}
}

func (ffiObject *FfiObject) incrementPointer(debugName string) C.uint64_t {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return rustCall(func(status *C.RustCallStatus) C.uint64_t {
		return ffiObject.cloneFunction(ffiObject.handle, status)
	})
}

func (ffiObject *FfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject) freeRustArcPtr() {
	if ffiObject.handle == 0 {
		return
	}
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.handle, status)
		return 0
	})
}

type GoCelEngineInterface interface {
	EngineName() string
	// Returns the engine's rules as a JSON array of rule infos.
	ListRulesJson() (string, error)
	// Validates a template and returns the detailed report as JSON.
	ValidateDetailedJson(template []byte, optionsJson string, filePath string) (string, error)
	// Validates a template and returns the standard report as JSON.
	ValidateStandardJson(template []byte, optionsJson string, filePath string) (string, error)
}
type GoCelEngine struct {
	ffiObject FfiObject
}

// Builds an engine from a JSON engine config (`{}` for defaults;
// `customRules` / `guardRules` load external rule sources).
func NewGoCelEngine(configJson string) (*GoCelEngine, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_bindings_go_fn_constructor_gocelengine_new(FfiConverterStringINSTANCE.Lower(configJson), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *GoCelEngine
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterGoCelEngineINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *GoCelEngine) EngineName() string {
	_pointer := _self.ffiObject.incrementPointer("*GoCelEngine")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gocelengine_engine_name(
				_pointer, _uniffiStatus),
		}
	}))
}

// Returns the engine's rules as a JSON array of rule infos.
func (_self *GoCelEngine) ListRulesJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoCelEngine")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gocelengine_list_rules_json(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Validates a template and returns the detailed report as JSON.
func (_self *GoCelEngine) ValidateDetailedJson(template []byte, optionsJson string, filePath string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoCelEngine")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gocelengine_validate_detailed_json(
				_pointer, FfiConverterBytesINSTANCE.Lower(template), FfiConverterStringINSTANCE.Lower(optionsJson), FfiConverterStringINSTANCE.Lower(filePath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Validates a template and returns the standard report as JSON.
func (_self *GoCelEngine) ValidateStandardJson(template []byte, optionsJson string, filePath string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoCelEngine")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gocelengine_validate_standard_json(
				_pointer, FfiConverterBytesINSTANCE.Lower(template), FfiConverterStringINSTANCE.Lower(optionsJson), FfiConverterStringINSTANCE.Lower(filePath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *GoCelEngine) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterGoCelEngine struct{}

var FfiConverterGoCelEngineINSTANCE = FfiConverterGoCelEngine{}

func (c FfiConverterGoCelEngine) Lift(handle C.uint64_t) *GoCelEngine {
	result := &GoCelEngine{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_bindings_go_fn_clone_gocelengine(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_bindings_go_fn_free_gocelengine(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*GoCelEngine).Destroy)
	return result
}

func (c FfiConverterGoCelEngine) Read(reader io.Reader) *GoCelEngine {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterGoCelEngine) Lower(value *GoCelEngine) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*GoCelEngine")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterGoCelEngine) Write(writer io.Writer, value *GoCelEngine) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalGoCelEngine(handle uint64) *GoCelEngine {
	return FfiConverterGoCelEngineINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalGoCelEngine(value *GoCelEngine) uint64 {
	return uint64(FfiConverterGoCelEngineINSTANCE.Lower(value))
}

type FfiDestroyerGoCelEngine struct{}

func (_ FfiDestroyerGoCelEngine) Destroy(value *GoCelEngine) {
	value.Destroy()
}

type GoRegoEngineInterface interface {
	EngineName() string
	// Returns the engine's rules as a JSON array of rule infos.
	ListRulesJson() (string, error)
	// Validates a template and returns the detailed report as JSON.
	ValidateDetailedJson(template []byte, optionsJson string, filePath string) (string, error)
	// Validates a template and returns the standard report as JSON.
	ValidateStandardJson(template []byte, optionsJson string, filePath string) (string, error)
}
type GoRegoEngine struct {
	ffiObject FfiObject
}

// Builds an engine from a JSON engine config (`{}` for defaults;
// `customRules` / `guardRules` load external rule sources).
func NewGoRegoEngine(configJson string) (*GoRegoEngine, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_bindings_go_fn_constructor_goregoengine_new(FfiConverterStringINSTANCE.Lower(configJson), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *GoRegoEngine
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterGoRegoEngineINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *GoRegoEngine) EngineName() string {
	_pointer := _self.ffiObject.incrementPointer("*GoRegoEngine")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_goregoengine_engine_name(
				_pointer, _uniffiStatus),
		}
	}))
}

// Returns the engine's rules as a JSON array of rule infos.
func (_self *GoRegoEngine) ListRulesJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoRegoEngine")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_goregoengine_list_rules_json(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Validates a template and returns the detailed report as JSON.
func (_self *GoRegoEngine) ValidateDetailedJson(template []byte, optionsJson string, filePath string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoRegoEngine")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_goregoengine_validate_detailed_json(
				_pointer, FfiConverterBytesINSTANCE.Lower(template), FfiConverterStringINSTANCE.Lower(optionsJson), FfiConverterStringINSTANCE.Lower(filePath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Validates a template and returns the standard report as JSON.
func (_self *GoRegoEngine) ValidateStandardJson(template []byte, optionsJson string, filePath string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoRegoEngine")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_goregoengine_validate_standard_json(
				_pointer, FfiConverterBytesINSTANCE.Lower(template), FfiConverterStringINSTANCE.Lower(optionsJson), FfiConverterStringINSTANCE.Lower(filePath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *GoRegoEngine) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterGoRegoEngine struct{}

var FfiConverterGoRegoEngineINSTANCE = FfiConverterGoRegoEngine{}

func (c FfiConverterGoRegoEngine) Lift(handle C.uint64_t) *GoRegoEngine {
	result := &GoRegoEngine{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_bindings_go_fn_clone_goregoengine(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_bindings_go_fn_free_goregoengine(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*GoRegoEngine).Destroy)
	return result
}

func (c FfiConverterGoRegoEngine) Read(reader io.Reader) *GoRegoEngine {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterGoRegoEngine) Lower(value *GoRegoEngine) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*GoRegoEngine")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterGoRegoEngine) Write(writer io.Writer, value *GoRegoEngine) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalGoRegoEngine(handle uint64) *GoRegoEngine {
	return FfiConverterGoRegoEngineINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalGoRegoEngine(value *GoRegoEngine) uint64 {
	return uint64(FfiConverterGoRegoEngineINSTANCE.Lower(value))
}

type FfiDestroyerGoRegoEngine struct{}

func (_ FfiDestroyerGoRegoEngine) Destroy(value *GoRegoEngine) {
	value.Destroy()
}

type GoSchemaValidatorInterface interface {
	// Returns the schema validator's rules as a JSON array of rule infos.
	ListRulesJson() (string, error)
	SchemaCount() uint32
	// Validates a parsed model against the provider schemas and returns the
	// diagnostics as a JSON array of standard diagnostics.
	ValidateJson(model *GoSemanticModel, region *string) (string, error)
}
type GoSchemaValidator struct {
	ffiObject FfiObject
}

func NewGoSchemaValidator(schemaConfigJson string) (*GoSchemaValidator, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_bindings_go_fn_constructor_goschemavalidator_new(FfiConverterStringINSTANCE.Lower(schemaConfigJson), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *GoSchemaValidator
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterGoSchemaValidatorINSTANCE.Lift(_uniffiRV), nil
	}
}

// Returns the schema validator's rules as a JSON array of rule infos.
func (_self *GoSchemaValidator) ListRulesJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSchemaValidator")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_goschemavalidator_list_rules_json(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *GoSchemaValidator) SchemaCount() uint32 {
	_pointer := _self.ffiObject.incrementPointer("*GoSchemaValidator")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_bindings_go_fn_method_goschemavalidator_schema_count(
			_pointer, _uniffiStatus)
	}))
}

// Validates a parsed model against the provider schemas and returns the
// diagnostics as a JSON array of standard diagnostics.
func (_self *GoSchemaValidator) ValidateJson(model *GoSemanticModel, region *string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSchemaValidator")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_goschemavalidator_validate_json(
				_pointer, FfiConverterGoSemanticModelINSTANCE.Lower(model), FfiConverterOptionalStringINSTANCE.Lower(region), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *GoSchemaValidator) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterGoSchemaValidator struct{}

var FfiConverterGoSchemaValidatorINSTANCE = FfiConverterGoSchemaValidator{}

func (c FfiConverterGoSchemaValidator) Lift(handle C.uint64_t) *GoSchemaValidator {
	result := &GoSchemaValidator{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_bindings_go_fn_clone_goschemavalidator(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_bindings_go_fn_free_goschemavalidator(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*GoSchemaValidator).Destroy)
	return result
}

func (c FfiConverterGoSchemaValidator) Read(reader io.Reader) *GoSchemaValidator {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterGoSchemaValidator) Lower(value *GoSchemaValidator) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*GoSchemaValidator")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterGoSchemaValidator) Write(writer io.Writer, value *GoSchemaValidator) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalGoSchemaValidator(handle uint64) *GoSchemaValidator {
	return FfiConverterGoSchemaValidatorINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalGoSchemaValidator(value *GoSchemaValidator) uint64 {
	return uint64(FfiConverterGoSchemaValidatorINSTANCE.Lower(value))
}

type FfiDestroyerGoSchemaValidator struct{}

func (_ FfiDestroyerGoSchemaValidator) Destroy(value *GoSchemaValidator) {
	value.Destroy()
}

type GoSemanticModelInterface interface {
	Conditions() ([]string, error)
	Description() *string
	FormatVersion() *string
	// Returns the template outputs as a JSON object keyed by name.
	OutputsJson() (string, error)
	// Returns the template parameters as a JSON object keyed by name.
	ParametersJson() (string, error)
	// Returns the resolved resources as a JSON object keyed by logical ID.
	ResourcesJson() (string, error)
	// Returns the source span for a template path as JSON, or None when the
	// path has no recorded location.
	SourceLocationJson(path string) (*string, error)
	// Returns the full diagnostic model as JSON.
	ToDiagnosticModelJson() (string, error)
	Transforms() ([]string, error)
}
type GoSemanticModel struct {
	ffiObject FfiObject
}

func GoSemanticModelParse(template []byte) (*GoSemanticModel, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_bindings_go_fn_constructor_gosemanticmodel_parse(FfiConverterBytesINSTANCE.Lower(template), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *GoSemanticModel
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterGoSemanticModelINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *GoSemanticModel) Conditions() ([]string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_conditions(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *GoSemanticModel) Description() *string {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterOptionalStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_description(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *GoSemanticModel) FormatVersion() *string {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterOptionalStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_format_version(
				_pointer, _uniffiStatus),
		}
	}))
}

// Returns the template outputs as a JSON object keyed by name.
func (_self *GoSemanticModel) OutputsJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_outputs_json(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Returns the template parameters as a JSON object keyed by name.
func (_self *GoSemanticModel) ParametersJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_parameters_json(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Returns the resolved resources as a JSON object keyed by logical ID.
func (_self *GoSemanticModel) ResourcesJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_resources_json(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Returns the source span for a template path as JSON, or None when the
// path has no recorded location.
func (_self *GoSemanticModel) SourceLocationJson(path string) (*string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_source_location_json(
				_pointer, FfiConverterStringINSTANCE.Lower(path), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOptionalStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// Returns the full diagnostic model as JSON.
func (_self *GoSemanticModel) ToDiagnosticModelJson() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_to_diagnostic_model_json(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *GoSemanticModel) Transforms() ([]string, error) {
	_pointer := _self.ffiObject.incrementPointer("*GoSemanticModel")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*ValidationError](FfiConverterValidationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_method_gosemanticmodel_transforms(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceStringINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *GoSemanticModel) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterGoSemanticModel struct{}

var FfiConverterGoSemanticModelINSTANCE = FfiConverterGoSemanticModel{}

func (c FfiConverterGoSemanticModel) Lift(handle C.uint64_t) *GoSemanticModel {
	result := &GoSemanticModel{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_bindings_go_fn_clone_gosemanticmodel(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_bindings_go_fn_free_gosemanticmodel(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*GoSemanticModel).Destroy)
	return result
}

func (c FfiConverterGoSemanticModel) Read(reader io.Reader) *GoSemanticModel {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterGoSemanticModel) Lower(value *GoSemanticModel) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*GoSemanticModel")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterGoSemanticModel) Write(writer io.Writer, value *GoSemanticModel) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalGoSemanticModel(handle uint64) *GoSemanticModel {
	return FfiConverterGoSemanticModelINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalGoSemanticModel(value *GoSemanticModel) uint64 {
	return uint64(FfiConverterGoSemanticModelINSTANCE.Lower(value))
}

type FfiDestroyerGoSemanticModel struct{}

func (_ FfiDestroyerGoSemanticModel) Destroy(value *GoSemanticModel) {
	value.Destroy()
}

type ValidationError struct {
	err error
}

// Convenience method to turn *ValidationError into error
// Avoiding treating nil pointer as non nil error interface
func (err *ValidationError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err ValidationError) Error() string {
	return fmt.Sprintf("ValidationError: %s", err.err.Error())
}

func (err ValidationError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrValidationErrorEngine = fmt.Errorf("ValidationErrorEngine")

// Variant structs
type ValidationErrorEngine struct {
	Msg string
}

func NewValidationErrorEngine(
	msg string,
) *ValidationError {
	return &ValidationError{err: &ValidationErrorEngine{
		Msg: msg}}
}

func (e ValidationErrorEngine) destroy() {
	FfiDestroyerString{}.Destroy(e.Msg)
}

func (err ValidationErrorEngine) Error() string {
	return fmt.Sprint("Engine",
		": ",

		"Msg=",
		err.Msg,
	)
}

func (self ValidationErrorEngine) Is(target error) bool {
	return target == ErrValidationErrorEngine
}

type FfiConverterValidationError struct{}

var FfiConverterValidationErrorINSTANCE = FfiConverterValidationError{}

func (c FfiConverterValidationError) Lift(eb RustBufferI) *ValidationError {
	return LiftFromRustBuffer[*ValidationError](c, eb)
}

func (c FfiConverterValidationError) Lower(value *ValidationError) C.RustBuffer {
	return LowerIntoRustBuffer[*ValidationError](c, value)
}

func (c FfiConverterValidationError) LowerExternal(value *ValidationError) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*ValidationError](c, value))
}

func (c FfiConverterValidationError) Read(reader io.Reader) *ValidationError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &ValidationError{&ValidationErrorEngine{
			Msg: FfiConverterStringINSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterValidationError.Read()", errorID))
	}
}

func (c FfiConverterValidationError) Write(writer io.Writer, value *ValidationError) {
	switch variantValue := value.err.(type) {
	case *ValidationErrorEngine:
		writeInt32(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Msg)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterValidationError.Write", value))
	}
}

type FfiDestroyerValidationError struct{}

func (_ FfiDestroyerValidationError) Destroy(value *ValidationError) {
	switch variantValue := value.err.(type) {
	case ValidationErrorEngine:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerValidationError.Destroy", value))
	}
}

type FfiConverterOptionalString struct{}

var FfiConverterOptionalStringINSTANCE = FfiConverterOptionalString{}

func (c FfiConverterOptionalString) Lift(rb RustBufferI) *string {
	return LiftFromRustBuffer[*string](c, rb)
}

func (_ FfiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalString) Lower(value *string) C.RustBuffer {
	return LowerIntoRustBuffer[*string](c, value)
}

func (c FfiConverterOptionalString) LowerExternal(value *string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*string](c, value))
}

func (_ FfiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalString struct{}

func (_ FfiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		FfiDestroyerString{}.Destroy(*value)
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) LowerExternal(value []string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]string](c, value))
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct{}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

func Version() string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_bindings_go_fn_func_version(_uniffiStatus),
		}
	}))
}
