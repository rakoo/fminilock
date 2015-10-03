package taber

const (
	CHUNK_SIZE            = 1048576
	FILENAME_BLOCK_LENGTH = (256 + 16 + 4)
	BLOCK_LENGTH          = CHUNK_SIZE + 16 + 4
)
