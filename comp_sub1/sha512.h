/*
* SHA-512 hash implementation
* Modified from https://github.com/pr0f3ss/SHA to handle binary input
*/

#pragma once
#include <cstdint>

void SHA512Digest(uint8_t* digest, uint8_t* input, size_t size);
