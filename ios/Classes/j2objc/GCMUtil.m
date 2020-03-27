//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/gcm/GCMUtil.java
//

#include "GCMUtil.h"
#include "IOSPrimitiveArray.h"
#include "Interleave.h"
#include "J2ObjC_source.h"
#include "Pack.h"

inline jint LibOrgBouncycastleCryptoModesGcmGCMUtil_get_E1(void);
#define LibOrgBouncycastleCryptoModesGcmGCMUtil_E1 -520093696
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoModesGcmGCMUtil, E1, jint)

inline jlong LibOrgBouncycastleCryptoModesGcmGCMUtil_get_E1L(void);
#define LibOrgBouncycastleCryptoModesGcmGCMUtil_E1L -2233785415175766016LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoModesGcmGCMUtil, E1L, jlong)

@implementation LibOrgBouncycastleCryptoModesGcmGCMUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSByteArray *)oneAsBytes {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_oneAsBytes();
}

+ (IOSIntArray *)oneAsInts {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_oneAsInts();
}

+ (IOSLongArray *)oneAsLongs {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_oneAsLongs();
}

+ (IOSByteArray *)asBytesWithIntArray:(IOSIntArray *)x {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_(x);
}

+ (void)asBytesWithIntArray:(IOSIntArray *)x
              withByteArray:(IOSByteArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_withByteArray_(x, z);
}

+ (IOSByteArray *)asBytesWithLongArray:(IOSLongArray *)x {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_(x);
}

+ (void)asBytesWithLongArray:(IOSLongArray *)x
               withByteArray:(IOSByteArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_withByteArray_(x, z);
}

+ (IOSIntArray *)asIntsWithByteArray:(IOSByteArray *)x {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_(x);
}

+ (void)asIntsWithByteArray:(IOSByteArray *)x
               withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_withIntArray_(x, z);
}

+ (IOSLongArray *)asLongsWithByteArray:(IOSByteArray *)x {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_(x);
}

+ (void)asLongsWithByteArray:(IOSByteArray *)x
               withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_withLongArray_(x, z);
}

+ (void)copy__WithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_copy__WithIntArray_withIntArray_(x, z);
}

+ (void)copy__WithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_copy__WithLongArray_withLongArray_(x, z);
}

+ (void)dividePWithLongArray:(IOSLongArray *)x
               withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_dividePWithLongArray_withLongArray_(x, z);
}

+ (void)multiplyWithByteArray:(IOSByteArray *)x
                withByteArray:(IOSByteArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyWithByteArray_withByteArray_(x, y);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyWithIntArray_withIntArray_(x, y);
}

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyWithLongArray_withLongArray_(x, y);
}

+ (void)multiplyPWithIntArray:(IOSIntArray *)x {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_(x);
}

+ (void)multiplyPWithIntArray:(IOSIntArray *)x
                 withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyPWithLongArray:(IOSLongArray *)x {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithLongArray_(x);
}

+ (void)multiplyPWithLongArray:(IOSLongArray *)x
                 withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithLongArray_withLongArray_(x, z);
}

+ (void)multiplyP3WithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP3WithLongArray_withLongArray_(x, z);
}

+ (void)multiplyP4WithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP4WithLongArray_withLongArray_(x, z);
}

+ (void)multiplyP7WithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP7WithLongArray_withLongArray_(x, z);
}

+ (void)multiplyP8WithIntArray:(IOSIntArray *)x {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_(x);
}

+ (void)multiplyP8WithIntArray:(IOSIntArray *)x
                  withIntArray:(IOSIntArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_withIntArray_(x, y);
}

+ (void)multiplyP8WithLongArray:(IOSLongArray *)x {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithLongArray_(x);
}

+ (void)multiplyP8WithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithLongArray_withLongArray_(x, y);
}

+ (IOSLongArray *)pAsLongs {
  return LibOrgBouncycastleCryptoModesGcmGCMUtil_pAsLongs();
}

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_squareWithLongArray_withLongArray_(x, z);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
             withByteArray:(IOSByteArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_(x, y);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
             withByteArray:(IOSByteArray *)y
                   withInt:(jint)yOff {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withInt_(x, y, yOff);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
                   withInt:(jint)xOff
             withByteArray:(IOSByteArray *)y
                   withInt:(jint)yOff
             withByteArray:(IOSByteArray *)z
                   withInt:(jint)zOff {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withInt_withByteArray_withInt_withByteArray_withInt_(x, xOff, y, yOff, z, zOff);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
             withByteArray:(IOSByteArray *)y
                   withInt:(jint)yOff
                   withInt:(jint)yLen {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withInt_withInt_(x, y, yOff, yLen);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
                   withInt:(jint)xOff
             withByteArray:(IOSByteArray *)y
                   withInt:(jint)yOff
                   withInt:(jint)len {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withInt_withByteArray_withInt_withInt_(x, xOff, y, yOff, len);
}

+ (void)xor__WithByteArray:(IOSByteArray *)x
             withByteArray:(IOSByteArray *)y
             withByteArray:(IOSByteArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withByteArray_(x, y, z);
}

+ (void)xor__WithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_(x, y);
}

+ (void)xor__WithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)y
             withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)xor__WithLongArray:(IOSLongArray *)x
             withLongArray:(IOSLongArray *)y {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_(x, y);
}

+ (void)xor__WithLongArray:(IOSLongArray *)x
             withLongArray:(IOSLongArray *)y
             withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 4, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 5, 7, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, 8, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 13, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 15, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 16, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 16, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 16, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 16, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 17, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 18, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 19, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 20, 12, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 21, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 15, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 23, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 24, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 25, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 26, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 27, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 28, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 22, 29, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(oneAsBytes);
  methods[2].selector = @selector(oneAsInts);
  methods[3].selector = @selector(oneAsLongs);
  methods[4].selector = @selector(asBytesWithIntArray:);
  methods[5].selector = @selector(asBytesWithIntArray:withByteArray:);
  methods[6].selector = @selector(asBytesWithLongArray:);
  methods[7].selector = @selector(asBytesWithLongArray:withByteArray:);
  methods[8].selector = @selector(asIntsWithByteArray:);
  methods[9].selector = @selector(asIntsWithByteArray:withIntArray:);
  methods[10].selector = @selector(asLongsWithByteArray:);
  methods[11].selector = @selector(asLongsWithByteArray:withLongArray:);
  methods[12].selector = @selector(copy__WithIntArray:withIntArray:);
  methods[13].selector = @selector(copy__WithLongArray:withLongArray:);
  methods[14].selector = @selector(dividePWithLongArray:withLongArray:);
  methods[15].selector = @selector(multiplyWithByteArray:withByteArray:);
  methods[16].selector = @selector(multiplyWithIntArray:withIntArray:);
  methods[17].selector = @selector(multiplyWithLongArray:withLongArray:);
  methods[18].selector = @selector(multiplyPWithIntArray:);
  methods[19].selector = @selector(multiplyPWithIntArray:withIntArray:);
  methods[20].selector = @selector(multiplyPWithLongArray:);
  methods[21].selector = @selector(multiplyPWithLongArray:withLongArray:);
  methods[22].selector = @selector(multiplyP3WithLongArray:withLongArray:);
  methods[23].selector = @selector(multiplyP4WithLongArray:withLongArray:);
  methods[24].selector = @selector(multiplyP7WithLongArray:withLongArray:);
  methods[25].selector = @selector(multiplyP8WithIntArray:);
  methods[26].selector = @selector(multiplyP8WithIntArray:withIntArray:);
  methods[27].selector = @selector(multiplyP8WithLongArray:);
  methods[28].selector = @selector(multiplyP8WithLongArray:withLongArray:);
  methods[29].selector = @selector(pAsLongs);
  methods[30].selector = @selector(squareWithLongArray:withLongArray:);
  methods[31].selector = @selector(xor__WithByteArray:withByteArray:);
  methods[32].selector = @selector(xor__WithByteArray:withByteArray:withInt:);
  methods[33].selector = @selector(xor__WithByteArray:withInt:withByteArray:withInt:withByteArray:withInt:);
  methods[34].selector = @selector(xor__WithByteArray:withByteArray:withInt:withInt:);
  methods[35].selector = @selector(xor__WithByteArray:withInt:withByteArray:withInt:withInt:);
  methods[36].selector = @selector(xor__WithByteArray:withByteArray:withByteArray:);
  methods[37].selector = @selector(xor__WithIntArray:withIntArray:);
  methods[38].selector = @selector(xor__WithIntArray:withIntArray:withIntArray:);
  methods[39].selector = @selector(xor__WithLongArray:withLongArray:);
  methods[40].selector = @selector(xor__WithLongArray:withLongArray:withLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "E1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoModesGcmGCMUtil_E1, 0x1a, -1, -1, -1, -1 },
    { "E1L", "J", .constantValue.asLong = LibOrgBouncycastleCryptoModesGcmGCMUtil_E1L, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "asBytes", "[I", "[I[B", "[J", "[J[B", "asInts", "[B", "[B[I", "asLongs", "[B[J", "copy", "[I[I", "[J[J", "divideP", "multiply", "[B[B", "multiplyP", "multiplyP3", "multiplyP4", "multiplyP7", "multiplyP8", "square", "xor", "[B[BI", "[BI[BI[BI", "[B[BII", "[BI[BII", "[B[B[B", "[I[I[I", "[J[J[J" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesGcmGCMUtil = { "GCMUtil", "lib.org.bouncycastle.crypto.modes.gcm", ptrTable, methods, fields, 7, 0x401, 41, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesGcmGCMUtil;
}

@end

void LibOrgBouncycastleCryptoModesGcmGCMUtil_init(LibOrgBouncycastleCryptoModesGcmGCMUtil *self) {
  NSObject_init(self);
}

IOSByteArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_oneAsBytes() {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:16];
  *IOSByteArray_GetRef(tmp, 0) = (jbyte) (jint) 0x80;
  return tmp;
}

IOSIntArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_oneAsInts() {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSIntArray *tmp = [IOSIntArray newArrayWithLength:4];
  *IOSIntArray_GetRef(tmp, 0) = JreLShift32(1, 31);
  return tmp;
}

IOSLongArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_oneAsLongs() {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSLongArray *tmp = [IOSLongArray newArrayWithLength:2];
  *IOSLongArray_GetRef(tmp, 0) = JreLShift64(1LL, 63);
  return tmp;
}

IOSByteArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_(IOSIntArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSByteArray *z = [IOSByteArray newArrayWithLength:16];
  LibOrgBouncycastleUtilPack_intToBigEndianWithIntArray_withByteArray_withInt_(x, z, 0);
  return z;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithIntArray_withByteArray_(IOSIntArray *x, IOSByteArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  LibOrgBouncycastleUtilPack_intToBigEndianWithIntArray_withByteArray_withInt_(x, z, 0);
}

IOSByteArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSByteArray *z = [IOSByteArray newArrayWithLength:16];
  LibOrgBouncycastleUtilPack_longToBigEndianWithLongArray_withByteArray_withInt_(x, z, 0);
  return z;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_withByteArray_(IOSLongArray *x, IOSByteArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  LibOrgBouncycastleUtilPack_longToBigEndianWithLongArray_withByteArray_withInt_(x, z, 0);
}

IOSIntArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_(IOSByteArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSIntArray *z = [IOSIntArray newArrayWithLength:4];
  LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_withIntArray_(x, 0, z);
  return z;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_asIntsWithByteArray_withIntArray_(IOSByteArray *x, IOSIntArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_withIntArray_(x, 0, z);
}

IOSLongArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_(IOSByteArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSLongArray *z = [IOSLongArray newArrayWithLength:2];
  LibOrgBouncycastleUtilPack_bigEndianToLongWithByteArray_withInt_withLongArray_(x, 0, z);
  return z;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_withLongArray_(IOSByteArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  LibOrgBouncycastleUtilPack_bigEndianToLongWithByteArray_withInt_withLongArray_(x, 0, z);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_copy__WithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  *IOSIntArray_GetRef(nil_chk(z), 0) = IOSIntArray_Get(nil_chk(x), 0);
  *IOSIntArray_GetRef(z, 1) = IOSIntArray_Get(x, 1);
  *IOSIntArray_GetRef(z, 2) = IOSIntArray_Get(x, 2);
  *IOSIntArray_GetRef(z, 3) = IOSIntArray_Get(x, 3);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_copy__WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_dividePWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong m = JreRShift64(x0, 63);
  x0 ^= (m & LibOrgBouncycastleCryptoModesGcmGCMUtil_E1L);
  *IOSLongArray_GetRef(nil_chk(z), 0) = (JreLShift64(x0, 1)) | (JreURShift64(x1, 63));
  *IOSLongArray_GetRef(z, 1) = (JreLShift64(x1, 1)) | -m;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyWithByteArray_withByteArray_(IOSByteArray *x, IOSByteArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSLongArray *t1 = LibOrgBouncycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_(x);
  IOSLongArray *t2 = LibOrgBouncycastleCryptoModesGcmGCMUtil_asLongsWithByteArray_(y);
  LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyWithLongArray_withLongArray_(t1, t2);
  LibOrgBouncycastleCryptoModesGcmGCMUtil_asBytesWithLongArray_withByteArray_(t1, x);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint y0 = IOSIntArray_Get(nil_chk(y), 0);
  jint y1 = IOSIntArray_Get(y, 1);
  jint y2 = IOSIntArray_Get(y, 2);
  jint y3 = IOSIntArray_Get(y, 3);
  jint z0 = 0;
  jint z1 = 0;
  jint z2 = 0;
  jint z3 = 0;
  for (jint i = 0; i < 4; ++i) {
    jint bits = IOSIntArray_Get(nil_chk(x), i);
    for (jint j = 0; j < 32; ++j) {
      jint m1 = JreRShift32(bits, 31);
      JreLShiftAssignInt(&bits, 1);
      z0 ^= (y0 & m1);
      z1 ^= (y1 & m1);
      z2 ^= (y2 & m1);
      z3 ^= (y3 & m1);
      jint m2 = JreRShift32((JreLShift32(y3, 31)), 8);
      y3 = (JreURShift32(y3, 1)) | (JreLShift32(y2, 31));
      y2 = (JreURShift32(y2, 1)) | (JreLShift32(y1, 31));
      y1 = (JreURShift32(y1, 1)) | (JreLShift32(y0, 31));
      y0 = (JreURShift32(y0, 1)) ^ (m2 & LibOrgBouncycastleCryptoModesGcmGCMUtil_E1);
    }
  }
  *IOSIntArray_GetRef(nil_chk(x), 0) = z0;
  *IOSIntArray_GetRef(x, 1) = z1;
  *IOSIntArray_GetRef(x, 2) = z2;
  *IOSIntArray_GetRef(x, 3) = z3;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong y0 = IOSLongArray_Get(nil_chk(y), 0);
  jlong y1 = IOSLongArray_Get(y, 1);
  jlong z0 = 0;
  jlong z1 = 0;
  jlong z2 = 0;
  for (jint j = 0; j < 64; ++j) {
    jlong m0 = JreRShift64(x0, 63);
    JreLShiftAssignLong(&x0, 1);
    z0 ^= (y0 & m0);
    z1 ^= (y1 & m0);
    jlong m1 = JreRShift64(x1, 63);
    JreLShiftAssignLong(&x1, 1);
    z1 ^= (y0 & m1);
    z2 ^= (y1 & m1);
    jlong c = JreRShift64((JreLShift64(y1, 63)), 8);
    y1 = (JreURShift64(y1, 1)) | (JreLShift64(y0, 63));
    y0 = (JreURShift64(y0, 1)) ^ (c & LibOrgBouncycastleCryptoModesGcmGCMUtil_E1L);
  }
  z0 ^= z2 ^ (JreURShift64(z2, 1)) ^ (JreURShift64(z2, 2)) ^ (JreURShift64(z2, 7));
  z1 ^= (JreLShift64(z2, 63)) ^ (JreLShift64(z2, 62)) ^ (JreLShift64(z2, 57));
  *IOSLongArray_GetRef(x, 0) = z0;
  *IOSLongArray_GetRef(x, 1) = z1;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_(IOSIntArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint x0 = IOSIntArray_Get(nil_chk(x), 0);
  jint x1 = IOSIntArray_Get(x, 1);
  jint x2 = IOSIntArray_Get(x, 2);
  jint x3 = IOSIntArray_Get(x, 3);
  jint m = JreRShift32((JreLShift32(x3, 31)), 31);
  *IOSIntArray_GetRef(x, 0) = (JreURShift32(x0, 1)) ^ (m & LibOrgBouncycastleCryptoModesGcmGCMUtil_E1);
  *IOSIntArray_GetRef(x, 1) = (JreURShift32(x1, 1)) | (JreLShift32(x0, 31));
  *IOSIntArray_GetRef(x, 2) = (JreURShift32(x2, 1)) | (JreLShift32(x1, 31));
  *IOSIntArray_GetRef(x, 3) = (JreURShift32(x3, 1)) | (JreLShift32(x2, 31));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint x0 = IOSIntArray_Get(nil_chk(x), 0);
  jint x1 = IOSIntArray_Get(x, 1);
  jint x2 = IOSIntArray_Get(x, 2);
  jint x3 = IOSIntArray_Get(x, 3);
  jint m = JreRShift32((JreLShift32(x3, 31)), 31);
  *IOSIntArray_GetRef(nil_chk(z), 0) = (JreURShift32(x0, 1)) ^ (m & LibOrgBouncycastleCryptoModesGcmGCMUtil_E1);
  *IOSIntArray_GetRef(z, 1) = (JreURShift32(x1, 1)) | (JreLShift32(x0, 31));
  *IOSIntArray_GetRef(z, 2) = (JreURShift32(x2, 1)) | (JreLShift32(x1, 31));
  *IOSIntArray_GetRef(z, 3) = (JreURShift32(x3, 1)) | (JreLShift32(x2, 31));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong m = JreRShift64((JreLShift64(x1, 63)), 63);
  *IOSLongArray_GetRef(x, 0) = (JreURShift64(x0, 1)) ^ (m & LibOrgBouncycastleCryptoModesGcmGCMUtil_E1L);
  *IOSLongArray_GetRef(x, 1) = (JreURShift64(x1, 1)) | (JreLShift64(x0, 63));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyPWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong m = JreRShift64((JreLShift64(x1, 63)), 63);
  *IOSLongArray_GetRef(nil_chk(z), 0) = (JreURShift64(x0, 1)) ^ (m & LibOrgBouncycastleCryptoModesGcmGCMUtil_E1L);
  *IOSLongArray_GetRef(z, 1) = (JreURShift64(x1, 1)) | (JreLShift64(x0, 63));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP3WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong c = JreLShift64(x1, 61);
  *IOSLongArray_GetRef(nil_chk(z), 0) = (JreURShift64(x0, 3)) ^ c ^ (JreURShift64(c, 1)) ^ (JreURShift64(c, 2)) ^ (JreURShift64(c, 7));
  *IOSLongArray_GetRef(z, 1) = (JreURShift64(x1, 3)) | (JreLShift64(x0, 61));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP4WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong c = JreLShift64(x1, 60);
  *IOSLongArray_GetRef(nil_chk(z), 0) = (JreURShift64(x0, 4)) ^ c ^ (JreURShift64(c, 1)) ^ (JreURShift64(c, 2)) ^ (JreURShift64(c, 7));
  *IOSLongArray_GetRef(z, 1) = (JreURShift64(x1, 4)) | (JreLShift64(x0, 60));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP7WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong c = JreLShift64(x1, 57);
  *IOSLongArray_GetRef(nil_chk(z), 0) = (JreURShift64(x0, 7)) ^ c ^ (JreURShift64(c, 1)) ^ (JreURShift64(c, 2)) ^ (JreURShift64(c, 7));
  *IOSLongArray_GetRef(z, 1) = (JreURShift64(x1, 7)) | (JreLShift64(x0, 57));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_(IOSIntArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint x0 = IOSIntArray_Get(nil_chk(x), 0);
  jint x1 = IOSIntArray_Get(x, 1);
  jint x2 = IOSIntArray_Get(x, 2);
  jint x3 = IOSIntArray_Get(x, 3);
  jint c = JreLShift32(x3, 24);
  *IOSIntArray_GetRef(x, 0) = (JreURShift32(x0, 8)) ^ c ^ (JreURShift32(c, 1)) ^ (JreURShift32(c, 2)) ^ (JreURShift32(c, 7));
  *IOSIntArray_GetRef(x, 1) = (JreURShift32(x1, 8)) | (JreLShift32(x0, 24));
  *IOSIntArray_GetRef(x, 2) = (JreURShift32(x2, 8)) | (JreLShift32(x1, 24));
  *IOSIntArray_GetRef(x, 3) = (JreURShift32(x3, 8)) | (JreLShift32(x2, 24));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint x0 = IOSIntArray_Get(nil_chk(x), 0);
  jint x1 = IOSIntArray_Get(x, 1);
  jint x2 = IOSIntArray_Get(x, 2);
  jint x3 = IOSIntArray_Get(x, 3);
  jint c = JreLShift32(x3, 24);
  *IOSIntArray_GetRef(nil_chk(y), 0) = (JreURShift32(x0, 8)) ^ c ^ (JreURShift32(c, 1)) ^ (JreURShift32(c, 2)) ^ (JreURShift32(c, 7));
  *IOSIntArray_GetRef(y, 1) = (JreURShift32(x1, 8)) | (JreLShift32(x0, 24));
  *IOSIntArray_GetRef(y, 2) = (JreURShift32(x2, 8)) | (JreLShift32(x1, 24));
  *IOSIntArray_GetRef(y, 3) = (JreURShift32(x3, 8)) | (JreLShift32(x2, 24));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong c = JreLShift64(x1, 56);
  *IOSLongArray_GetRef(x, 0) = (JreURShift64(x0, 8)) ^ c ^ (JreURShift64(c, 1)) ^ (JreURShift64(c, 2)) ^ (JreURShift64(c, 7));
  *IOSLongArray_GetRef(x, 1) = (JreURShift64(x1, 8)) | (JreLShift64(x0, 56));
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_multiplyP8WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong x1 = IOSLongArray_Get(x, 1);
  jlong c = JreLShift64(x1, 56);
  *IOSLongArray_GetRef(nil_chk(y), 0) = (JreURShift64(x0, 8)) ^ c ^ (JreURShift64(c, 1)) ^ (JreURShift64(c, 2)) ^ (JreURShift64(c, 7));
  *IOSLongArray_GetRef(y, 1) = (JreURShift64(x1, 8)) | (JreLShift64(x0, 56));
}

IOSLongArray *LibOrgBouncycastleCryptoModesGcmGCMUtil_pAsLongs() {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSLongArray *tmp = [IOSLongArray newArrayWithLength:2];
  *IOSLongArray_GetRef(tmp, 0) = JreLShift64(1LL, 62);
  return tmp;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  IOSLongArray *t = [IOSLongArray newArrayWithLength:4];
  LibOrgBouncycastleMathRawInterleave_expand64To128RevWithLong_withLongArray_withInt_(IOSLongArray_Get(nil_chk(x), 0), t, 0);
  LibOrgBouncycastleMathRawInterleave_expand64To128RevWithLong_withLongArray_withInt_(IOSLongArray_Get(x, 1), t, 2);
  jlong z0 = IOSLongArray_Get(t, 0);
  jlong z1 = IOSLongArray_Get(t, 1);
  jlong z2 = IOSLongArray_Get(t, 2);
  jlong z3 = IOSLongArray_Get(t, 3);
  z1 ^= z3 ^ (JreURShift64(z3, 1)) ^ (JreURShift64(z3, 2)) ^ (JreURShift64(z3, 7));
  z2 ^= (JreLShift64(z3, 63)) ^ (JreLShift64(z3, 62)) ^ (JreLShift64(z3, 57));
  z0 ^= z2 ^ (JreURShift64(z2, 1)) ^ (JreURShift64(z2, 2)) ^ (JreURShift64(z2, 7));
  z1 ^= (JreLShift64(z2, 63)) ^ (JreLShift64(z2, 62)) ^ (JreLShift64(z2, 57));
  *IOSLongArray_GetRef(nil_chk(z), 0) = z0;
  *IOSLongArray_GetRef(z, 1) = z1;
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_(IOSByteArray *x, IOSByteArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint i = 0;
  do {
    *IOSByteArray_GetRef(nil_chk(x), i) ^= IOSByteArray_Get(nil_chk(y), i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, i);
    ++i;
  }
  while (i < 16);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withInt_(IOSByteArray *x, IOSByteArray *y, jint yOff) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint i = 0;
  do {
    *IOSByteArray_GetRef(nil_chk(x), i) ^= IOSByteArray_Get(nil_chk(y), yOff + i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, yOff + i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, yOff + i);
    ++i;
    *IOSByteArray_GetRef(x, i) ^= IOSByteArray_Get(y, yOff + i);
    ++i;
  }
  while (i < 16);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withInt_withByteArray_withInt_withByteArray_withInt_(IOSByteArray *x, jint xOff, IOSByteArray *y, jint yOff, IOSByteArray *z, jint zOff) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint i = 0;
  do {
    *IOSByteArray_GetRef(nil_chk(z), zOff + i) = (jbyte) (IOSByteArray_Get(nil_chk(x), xOff + i) ^ IOSByteArray_Get(nil_chk(y), yOff + i));
    ++i;
    *IOSByteArray_GetRef(z, zOff + i) = (jbyte) (IOSByteArray_Get(x, xOff + i) ^ IOSByteArray_Get(y, yOff + i));
    ++i;
    *IOSByteArray_GetRef(z, zOff + i) = (jbyte) (IOSByteArray_Get(x, xOff + i) ^ IOSByteArray_Get(y, yOff + i));
    ++i;
    *IOSByteArray_GetRef(z, zOff + i) = (jbyte) (IOSByteArray_Get(x, xOff + i) ^ IOSByteArray_Get(y, yOff + i));
    ++i;
  }
  while (i < 16);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withInt_withInt_(IOSByteArray *x, IOSByteArray *y, jint yOff, jint yLen) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  while (--yLen >= 0) {
    *IOSByteArray_GetRef(nil_chk(x), yLen) ^= IOSByteArray_Get(nil_chk(y), yOff + yLen);
  }
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withInt_withByteArray_withInt_withInt_(IOSByteArray *x, jint xOff, IOSByteArray *y, jint yOff, jint len) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  while (--len >= 0) {
    *IOSByteArray_GetRef(nil_chk(x), xOff + len) ^= IOSByteArray_Get(nil_chk(y), yOff + len);
  }
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithByteArray_withByteArray_withByteArray_(IOSByteArray *x, IOSByteArray *y, IOSByteArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  jint i = 0;
  do {
    *IOSByteArray_GetRef(nil_chk(z), i) = (jbyte) (IOSByteArray_Get(nil_chk(x), i) ^ IOSByteArray_Get(nil_chk(y), i));
    ++i;
    *IOSByteArray_GetRef(z, i) = (jbyte) (IOSByteArray_Get(x, i) ^ IOSByteArray_Get(y, i));
    ++i;
    *IOSByteArray_GetRef(z, i) = (jbyte) (IOSByteArray_Get(x, i) ^ IOSByteArray_Get(y, i));
    ++i;
    *IOSByteArray_GetRef(z, i) = (jbyte) (IOSByteArray_Get(x, i) ^ IOSByteArray_Get(y, i));
    ++i;
  }
  while (i < 16);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  *IOSIntArray_GetRef(nil_chk(x), 0) ^= IOSIntArray_Get(nil_chk(y), 0);
  *IOSIntArray_GetRef(x, 1) ^= IOSIntArray_Get(y, 1);
  *IOSIntArray_GetRef(x, 2) ^= IOSIntArray_Get(y, 2);
  *IOSIntArray_GetRef(x, 3) ^= IOSIntArray_Get(y, 3);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  *IOSIntArray_GetRef(nil_chk(z), 0) = IOSIntArray_Get(nil_chk(x), 0) ^ IOSIntArray_Get(nil_chk(y), 0);
  *IOSIntArray_GetRef(z, 1) = IOSIntArray_Get(x, 1) ^ IOSIntArray_Get(y, 1);
  *IOSIntArray_GetRef(z, 2) = IOSIntArray_Get(x, 2) ^ IOSIntArray_Get(y, 2);
  *IOSIntArray_GetRef(z, 3) = IOSIntArray_Get(x, 3) ^ IOSIntArray_Get(y, 3);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  *IOSLongArray_GetRef(nil_chk(x), 0) ^= IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(x, 1) ^= IOSLongArray_Get(y, 1);
}

void LibOrgBouncycastleCryptoModesGcmGCMUtil_xor__WithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  LibOrgBouncycastleCryptoModesGcmGCMUtil_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1) ^ IOSLongArray_Get(y, 1);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesGcmGCMUtil)
