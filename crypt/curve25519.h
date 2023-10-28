#include <stdint.h>

#pragma once

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519(u8* mypublic, const u8* secret, const u8* basepoint);