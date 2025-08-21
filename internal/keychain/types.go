//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import "unsafe"

var (
	nilCFStringRef C.CFStringRef
	nilCFDataRef   C.CFDataRef
)

// stringToCFString creates a new CFStringRef from a Go string.
// It properly handles the allocation and freeing of the intermediate C string.
// The caller is responsible for calling C.CFRelease on the returned CFStringRef.
func stringToCFString(s string) C.CFStringRef {
	cString := C.CString(s)
	defer C.free(unsafe.Pointer(cString))
	return C.CFStringCreateWithCString(C.kCFAllocatorDefault, cString, C.kCFStringEncodingUTF8)
}

// stringFromCFString converts a CFStringRef into a new Go string.
func stringFromCFString(cfString C.CFStringRef) string {
	if cfString == nilCFStringRef {
		return ""
	}
	// Fast path: try to get a direct pointer to the C string.
	// This is a "borrowed" pointer, so we don't free it.
	cStr := C.CFStringGetCStringPtr(cfString, C.kCFStringEncodingUTF8)
	if cStr != nil {
		return C.GoString(cStr)
	}

	// Slow path: if a direct pointer is not available, we must copy the bytes.
	length := C.CFStringGetLength(cfString)
	if length == 0 {
		return ""
	}
	maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)

	// Allocate a buffer on the C heap, which is safer than using a Go slice.
	buffer := C.malloc(C.size_t(maxSize))
	defer C.free(buffer)

	if C.CFStringGetCString(cfString, (*C.char)(buffer), maxSize, C.kCFStringEncodingUTF8) == C.true {
		return C.GoString((*C.char)(buffer))
	}

	return ""
}

// mapToCFDictionary creates a new CFDictionaryRef from a Go map using unsafe.Slice.
// It safely allocates temporary C arrays for the keys and values.
// The caller is responsible for calling C.CFRelease on the returned dictionary.
func mapToCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	count := len(m)

	// Handle the edge case of an empty map.
	if count == 0 {
		return C.CFDictionaryCreate(C.kCFAllocatorDefault, nil, nil, 0,
			&C.kCFTypeDictionaryKeyCallBacks,
			&C.kCFTypeDictionaryValueCallBacks)
	}

	keysPtr := C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(unsafe.Pointer(nil))))
	defer C.free(keysPtr)

	valsPtr := C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(unsafe.Pointer(nil))))
	defer C.free(valsPtr)

	keysSlice := unsafe.Slice((*unsafe.Pointer)(keysPtr), count)
	valsSlice := unsafe.Slice((*unsafe.Pointer)(valsPtr), count)

	i := 0
	for k, v := range m {
		keysSlice[i] = unsafe.Pointer(k) //nolint:govet // C memory to C memory
		valsSlice[i] = unsafe.Pointer(v) //nolint:govet // C memory to C memory
		i++
	}

	ref := C.CFDictionaryCreate(C.kCFAllocatorDefault,
		(*unsafe.Pointer)(keysPtr), // Pointer to the C array of keys
		(*unsafe.Pointer)(valsPtr), // Pointer to the C array of values
		C.CFIndex(count),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks)

	return ref
}

// mapFromCFDictionary converts a CFDictionaryRef into a Go map.
//
// The keys and values in the returned map are C.CFTypeRef. The caller is
// responsible for converting them to more specific types (e.g., CFStringRef
// to a Go string) if needed.
//
// IMPORTANT: The pointers in the returned map are "borrowed references" from
// the input dictionary. Their validity is tied to the lifetime of the input
// `dict`. You DO NOT own them and MUST NOT call C.CFRelease on them.
func mapFromCFDictionary(dict C.CFDictionaryRef) map[C.CFTypeRef]C.CFTypeRef {
	count := C.CFDictionaryGetCount(dict)
	if count == 0 {
		return make(map[C.CFTypeRef]C.CFTypeRef)
	}

	// Allocate memory on the C heap to store the keys and values. The size is
	// the number of items multiplied by the size of a pointer.
	keysPtr := C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(unsafe.Pointer(nil))))
	defer C.free(keysPtr)

	valsPtr := C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(unsafe.Pointer(nil))))
	defer C.free(valsPtr)

	// populate our C arrays with pointers from the dictionary.
	C.CFDictionaryGetKeysAndValues(dict,
		(*unsafe.Pointer)(keysPtr),
		(*unsafe.Pointer)(valsPtr),
	)

	keysSlice := unsafe.Slice((*unsafe.Pointer)(keysPtr), count)
	valsSlice := unsafe.Slice((*unsafe.Pointer)(valsPtr), count)

	goMap := make(map[C.CFTypeRef]C.CFTypeRef, count)
	for i := 0; i < int(count); i++ {
		key := C.CFTypeRef(keysSlice[i])
		value := C.CFTypeRef(valsSlice[i])
		goMap[key] = value
	}

	return goMap
}

// bytesToCFData creates a new CFDataRef from a Go byte slice.
// It properly handles the allocation and freeing of the intermediate C buffer.
// The caller is responsible for calling C.CFRelease on the returned CFDataRef.
func bytesToCFData(data []byte) C.CFDataRef {
	if len(data) == 0 {
		// CFDataCreate with a NULL pointer and 0 length is the correct way
		// to create an empty CFData object.
		return C.CFDataCreate(C.kCFAllocatorDefault, nil, 0)
	}

	cBytes := C.CBytes(data)
	defer C.free(cBytes)

	// CFDataCreate copies the data from our temporary C buffer, so we can free
	// the buffer immediately after the call.
	return C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(cBytes), C.CFIndex(len(data)))
}

// bytesFromCFData converts a CFDataRef into a new Go byte slice.
// It creates a copy of the data from the CFData object.
func bytesFromCFData(data C.CFDataRef) []byte {
	if data == nilCFDataRef {
		return nil
	}
	length := C.CFDataGetLength(data)
	if length == 0 {
		return []byte{}
	}

	// Try to get a direct pointer to the data's internal buffer.
	// This is the most efficient path.
	ptr := C.CFDataGetBytePtr(data)

	if ptr != nil {
		// C.GoBytes creates a new Go slice and copies the C data into it.
		// This is the preferred and safest way to copy the data.
		return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	}

	// If a direct pointer is not available (e.g., the data is stored
	// non-contiguously), we must copy the bytes manually.
	bytes := make([]byte, length)
	byteRange := C.CFRange{location: 0, length: length}
	C.CFDataGetBytes(data, byteRange, (*C.UInt8)(&bytes[0]))
	return bytes
}

// sliceToCFArray creates a new CFArrayRef from a Go slice of CFTypeRef. It safely
// allocates a temporary C array for the values. The caller is responsible for
// calling C.CFRelease on the returned CFArrayRef.
func sliceToCFArray(slice []C.CFTypeRef) C.CFArrayRef {
	count := len(slice)
	if count == 0 {
		return C.CFArrayCreate(C.kCFAllocatorDefault, nil, 0, &C.kCFTypeArrayCallBacks)
	}

	valsPtr := C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(unsafe.Pointer(nil))))
	defer C.free(valsPtr)

	valsSlice := unsafe.Slice((*unsafe.Pointer)(valsPtr), count)

	for i, v := range slice {
		valsSlice[i] = unsafe.Pointer(v) //nolint:govet // C memory to C memory
	}

	// 4. Call the C function, passing a pointer to the C-managed array.
	ref := C.CFArrayCreate(C.kCFAllocatorDefault,
		(*unsafe.Pointer)(valsPtr),
		C.CFIndex(count),
		&C.kCFTypeArrayCallBacks)

	return ref
}

// goSliceFromCFArray converts a CFArrayRef into a new Go slice of CFTypeRef.
//
// IMPORTANT: The pointers in the returned slice are "borrowed references" from
// the input array. Their validity is tied to the lifetime of the input `array`.
// You DO NOT own them and MUST NOT call C.CFRelease on them.
func goSliceFromCFArray(array C.CFArrayRef) []C.CFTypeRef {
	count := C.CFArrayGetCount(array)
	if count == 0 {
		return []C.CFTypeRef{}
	}

	valsPtr := C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(unsafe.Pointer(nil))))
	defer C.free(valsPtr)

	valueRange := C.CFRange{location: 0, length: count}
	C.CFArrayGetValues(array, valueRange, (*unsafe.Pointer)(valsPtr))

	valsSlice := unsafe.Slice((*unsafe.Pointer)(valsPtr), count)

	goSlice := make([]C.CFTypeRef, count)
	for i, v := range valsSlice {
		goSlice[i] = C.CFTypeRef(v)
	}

	return goSlice
}
