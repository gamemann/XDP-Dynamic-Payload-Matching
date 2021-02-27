#include <inttypes.h>

#define MAX_PAYLOAD_LENGTH 12

struct payload
{
    uint16_t length;
    uint8_t payload[MAX_PAYLOAD_LENGTH];
};