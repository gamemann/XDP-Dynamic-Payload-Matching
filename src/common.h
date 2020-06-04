#include <inttypes.h>

#define MAX_PAYLOAD_LENGTH 1500

struct payload
{
    uint16_t length;
    uint8_t payload[MAX_PAYLOAD_LENGTH];
};