#include "lzokay-c.h"
#include "../lzokay.hpp"

extern "C"
int lzokay_decompress(const uint8_t * src, size_t src_size, uint8_t *output, size_t *output_len)
{
    EResult error = decompress(src, src_size, output, *output_len, output_len);
    if (error < EResult_Success)
        return LZOKAY_ERROR;
    return LZOKAY_SUCCESS;
}
