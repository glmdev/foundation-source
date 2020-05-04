#include "lzokay-c.h"
#include "../lzokay.hpp"

extern "C"
int lzokay_decompress(const uint8_t * src, size_t src_size, uint8_t *output, size_t *output_len)
{
    size_t needed_size = 0;
    EResult error =
        lzokay::decompress(src, src_size, output, *output_len, needed_size);
    if (error < EResult_Success)
        return LZOKAY_ERROR;
    *output_len = needed_size;
    return LZOKAY_SUCCESS;
}
