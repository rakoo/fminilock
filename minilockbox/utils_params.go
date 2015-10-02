package minilockbox

const chunk_size = 1048576
const filename_block_length = (256 + 16 + 4)
const block_length = chunk_size + 16 + 4
