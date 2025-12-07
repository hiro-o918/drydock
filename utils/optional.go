package utils

func IsZero[T comparable](v T) bool {
	var zero T // zero will hold the zero value for type T
	return v == zero
}

func ToPtr[T comparable](v T) *T {
	if IsZero(v) {
		return nil
	}
	return &v
}
