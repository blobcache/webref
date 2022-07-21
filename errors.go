package webref

import "fmt"

type ErrAlgoUnsupported struct {
	Algo string
	Type string
}

func (e ErrAlgoUnsupported) Error() string {
	return fmt.Sprintf("webref: resolver does not support %s algorithm %q", e.Type, e.Algo)
}

type ErrSliceOOB struct {
	SliceStage
}

func (e ErrSliceOOB) Error() string {
	return fmt.Sprintf("webref: slice indices out of bounds begin: %d, end: %d", e.Begin, e.End)
}

type ErrEmptyStage struct{}

func (e ErrEmptyStage) Error() string {
	return fmt.Sprintf("webref: stage is empty")
}
