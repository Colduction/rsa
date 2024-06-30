package rsa

type (
	EmptyInputError uint8
	NilInputError   uint8
)

func (EmptyInputError) Error() string {
	return "rsa: input is empty"
}

func (NilInputError) Error() string {
	return "rsa: input is nil"
}
