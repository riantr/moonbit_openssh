/**
 * Loop #13 known_hosts test vectors (generated from knownhosts_python_ref.py)
 * DO NOT MODIFY BY HAND - re-run gen_knownhosts_test.py to update
 */
#ifndef _KNOWNHOSTS_KAT_H_
#define _KNOWNHOSTS_KAT_H_

#include <stddef.h>
#include <stdint.h>

static const uint8_t V1_BLOB[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x79, 0xb5, 0x56, 0x2e, 0x8f,
  0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 0x90,
  0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad,
  0x04, 0x96, 0x64,
};
static const size_t V1_BLOB_len = 51;

static const uint8_t V4_BLOB[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0xba, 0xfc, 0x71, 0xbe, 0xad,
  0x3a, 0xc5, 0xe4, 0xb6, 0x3e, 0x9c, 0x82, 0x16, 0xee, 0x71, 0xa3, 0x4a,
  0xae, 0xc6, 0x57, 0x22, 0xee, 0xdb, 0xca, 0x72, 0x8b, 0x4e, 0x9b, 0x3c,
  0xcc, 0xe3, 0x96,
};
static const size_t V4_BLOB_len = 51;

static const uint8_t V5_BLOB[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0xba, 0xfc, 0x71, 0xbe, 0xad,
  0x3a, 0xc5, 0xe4, 0xb6, 0x3e, 0x9c, 0x82, 0x16, 0xee, 0x71, 0xa3, 0x4a,
  0xae, 0xc6, 0x57, 0x22, 0xee, 0xdb, 0xca, 0x72, 0x8b, 0x4e, 0x9b, 0x3c,
  0xcc, 0xe3, 0x96,
};
static const size_t V5_BLOB_len = 51;

static const uint8_t V4_SALT[20] = {
  0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x5f, 0x73, 0x61, 0x6c, 0x74, 0x5f,
  0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00,
};
static const size_t V4_SALT_len = 20;

static const uint8_t V4_HASH[20] = {
  0x84, 0x24, 0x81, 0xfa, 0x15, 0xa3, 0x4f, 0xb7, 0x1d, 0x75, 0x04, 0x45,
  0x67, 0x31, 0xcd, 0x9c, 0xa2, 0xd8, 0xbb, 0x76,
};
static const size_t V4_HASH_len = 20;

static const uint8_t V8_PK_A[32] = {
  0x79, 0xb5, 0x56, 0x2e, 0x8f, 0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12,
  0xe8, 0xa9, 0x8b, 0xa7, 0x90, 0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7,
  0xe0, 0xe3, 0x91, 0x0b, 0xad, 0x04, 0x96, 0x64,
};
static const size_t V8_PK_A_len = 32;

static const uint8_t V8_PK_B[32] = {
  0xba, 0xfc, 0x71, 0xbe, 0xad, 0x3a, 0xc5, 0xe4, 0xb6, 0x3e, 0x9c, 0x82,
  0x16, 0xee, 0x71, 0xa3, 0x4a, 0xae, 0xc6, 0x57, 0x22, 0xee, 0xdb, 0xca,
  0x72, 0x8b, 0x4e, 0x9b, 0x3c, 0xcc, 0xe3, 0x96,
};
static const size_t V8_PK_B_len = 32;

static const uint8_t V8_BLOB_A[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x79, 0xb5, 0x56, 0x2e, 0x8f,
  0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 0x90,
  0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad,
  0x04, 0x96, 0x64,
};
static const size_t V8_BLOB_A_len = 51;

static const uint8_t V8_BLOB_B[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0xba, 0xfc, 0x71, 0xbe, 0xad,
  0x3a, 0xc5, 0xe4, 0xb6, 0x3e, 0x9c, 0x82, 0x16, 0xee, 0x71, 0xa3, 0x4a,
  0xae, 0xc6, 0x57, 0x22, 0xee, 0xdb, 0xca, 0x72, 0x8b, 0x4e, 0x9b, 0x3c,
  0xcc, 0xe3, 0x96,
};
static const size_t V8_BLOB_B_len = 51;

static const uint8_t V0_SHA1_EMPTY[20] = {
  0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef,
  0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
};
static const size_t V0_SHA1_EMPTY_len = 20;

static const uint8_t V0_SHA1_ABC[20] = {
  0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71,
  0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
};
static const size_t V0_SHA1_ABC_len = 20;

static const uint8_t V0_SHA1_LONG[20] = {
  0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1,
  0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
};
static const size_t V0_SHA1_LONG_len = 20;

static const uint8_t V0B_HMAC_CASE1[20] = {
  0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6,
  0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
};
static const size_t V0B_HMAC_CASE1_len = 20;

static const uint8_t V0B_HMAC_CASE2[20] = {
  0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5,
  0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
};
static const size_t V0B_HMAC_CASE2_len = 20;

static const uint8_t V9_PRESENTED_BLOB[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x79, 0xb5, 0x56, 0x2e, 0x8f,
  0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 0x90,
  0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad,
  0x04, 0x96, 0x64,
};
static const size_t V9_PRESENTED_BLOB_len = 51;

static const uint8_t V10_PRESENTED_BLOB[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x79, 0xb5, 0x56, 0x2e, 0x8f,
  0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 0x90,
  0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad,
  0x04, 0x96, 0x64,
};
static const size_t V10_PRESENTED_BLOB_len = 51;

static const uint8_t V11_PRESENTED_BLOB[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x79, 0xb5, 0x56, 0x2e, 0x8f,
  0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 0x90,
  0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad,
  0x04, 0x96, 0x64,
};
static const size_t V11_PRESENTED_BLOB_len = 51;

static const uint8_t V12_PRESENTED_BLOB[51] = {
  0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x79, 0xb5, 0x56, 0x2e, 0x8f,
  0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 0x90,
  0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad,
  0x04, 0x96, 0x64,
};
static const size_t V12_PRESENTED_BLOB_len = 51;

static const char V1_HOST[] = { 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V1_HOST_len = 15;

static const char V2_HOST[] = { 98, 97, 114, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V2_HOST_len = 15;

static const char V3_HOST[] = { 103, 111, 111, 100, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V3_HOST_len = 16;

static const char V4_HOST[] = { 104, 97, 115, 104, 101, 100, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V4_HOST_len = 18;

static const char V5_HOST[] = { 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V5_HOST_len = 15;

static const char V6_HOST[] = { 117, 110, 107, 110, 111, 119, 110, 46, 101, 120, 97, 109, 112, 108, 101, 46, 111, 114, 103, 0 };
static const size_t V6_HOST_len = 19;

static const char V7_HOST[] = { 117, 110, 107, 110, 111, 119, 110, 46, 101, 120, 97, 109, 112, 108, 101, 46, 111, 114, 103, 0 };
static const size_t V7_HOST_len = 19;

static const char V9_HOST[] = { 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V9_HOST_len = 15;

static const char V10_HOST[] = { 91, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 93, 58, 50, 50, 48, 48, 0 };
static const size_t V10_HOST_len = 22;

static const char V11_HOST[] = { 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V11_HOST_len = 15;

static const char V12_HOST[] = { 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0 };
static const size_t V12_HOST_len = 15;

#define V1_STATUS 0
#define V2_STATUS 0
#define V3_STATUS 0
#define V4_STATUS 0
#define V5_STATUS 1
#define V6_STATUS 2
#define V7_STATUS 3
#define V9_STATUS 0
#define V10_STATUS 0
#define V11_STATUS 2
#define V12_STATUS 1
#define V9_PORT 0
#define V10_PORT 2200
#define V11_PORT 0
#define V12_PORT 0

/* HOST_OK=0 HOST_MISMATCH=1 HOST_UNKNOWN=2 HOST_INVALID=3 */

static const char V1_KH_LINE[] = { 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 44, 42, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V1_KH_LINE_len = 106;

static const char V3_KH_LINE[] = { 33, 98, 97, 100, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 44, 103, 111, 111, 100, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 44, 42, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V3_KH_LINE_len = 128;

static const char V4_KH_LINE[] = { 124, 49, 124, 97, 71, 70, 122, 97, 71, 86, 107, 88, 51, 78, 104, 98, 72, 82, 102, 77, 68, 69, 121, 77, 119, 65, 65, 65, 65, 65, 124, 104, 67, 83, 66, 43, 104, 87, 106, 84, 55, 99, 100, 100, 81, 82, 70, 90, 122, 72, 78, 110, 75, 76, 89, 117, 51, 89, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 76, 114, 56, 99, 98, 54, 116, 79, 115, 88, 107, 116, 106, 54, 99, 103, 104, 98, 117, 99, 97, 78, 75, 114, 115, 90, 88, 73, 117, 55, 98, 121, 110, 75, 76, 84, 112, 115, 56, 122, 79, 79, 87, 0 };
static const size_t V4_KH_LINE_len = 139;

static const char V5_KH_LINE[] = { 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V5_KH_LINE_len = 96;

static const char V6_KH_LINE[] = { 107, 110, 111, 119, 110, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V6_KH_LINE_len = 98;

static const char V7_KH_LINE[] = { 107, 110, 111, 119, 110, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V7_KH_LINE_len = 98;

static const char V9_KH_LINE[] = { 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V9_KH_LINE_len = 96;

static const char V10_KH_LINE[] = { 91, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 93, 58, 50, 50, 48, 48, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V10_KH_LINE_len = 103;

static const char V11_KH_LINE[] = { 91, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 93, 58, 50, 50, 48, 48, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V11_KH_LINE_len = 103;

static const char V12_KH_LINE[] = { 64, 114, 101, 118, 111, 107, 101, 100, 32, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 32, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 32, 65, 65, 65, 65, 67, 51, 78, 122, 97, 67, 49, 108, 90, 68, 73, 49, 78, 84, 69, 53, 65, 65, 65, 65, 73, 72, 109, 49, 86, 105, 54, 80, 53, 108, 84, 53, 81, 72, 105, 120, 69, 117, 105, 112, 105, 54, 101, 81, 72, 52, 85, 54, 53, 112, 87, 43, 49, 43, 68, 106, 107, 81, 117, 116, 66, 74, 90, 107, 0 };
static const size_t V12_KH_LINE_len = 105;

#endif // _KNOWNHOSTS_KAT_H_
