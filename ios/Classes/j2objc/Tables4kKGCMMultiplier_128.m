//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/kgcm/Tables4kKGCMMultiplier_128.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KGCMUtil_128.h"
#include "Tables4kKGCMMultiplier_128.h"

@interface LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128 () {
 @public
  IOSObjectArray *T_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128, T_, IOSObjectArray *)

@implementation LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLongArray:(IOSLongArray *)H {
  if (T_ == nil) {
    T_ = [IOSLongArray newArrayWithDimensions:2 lengths:(jint[]){ 256, LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_SIZE }];
  }
  else if (LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_equalWithLongArray_withLongArray_(H, IOSObjectArray_Get(T_, 1))) {
    return;
  }
  LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_copy__WithLongArray_withLongArray_(H, IOSObjectArray_Get(nil_chk(T_), 1));
  for (jint n = 2; n < 256; n += 2) {
    LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_multiplyXWithLongArray_withLongArray_(IOSObjectArray_Get(nil_chk(T_), JreRShift32(n, 1)), IOSObjectArray_Get(T_, n));
    LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_addWithLongArray_withLongArray_withLongArray_(IOSObjectArray_Get(nil_chk(T_), n), IOSObjectArray_Get(T_, 1), IOSObjectArray_Get(T_, n + 1));
  }
}

- (void)multiplyHWithLongArray:(IOSLongArray *)z {
  IOSLongArray *r = [IOSLongArray newArrayWithLength:LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_SIZE];
  LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_copy__WithLongArray_withLongArray_(IOSObjectArray_Get(nil_chk(T_), (jint) (JreURShift64(IOSLongArray_Get(nil_chk(z), LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_SIZE - 1), 56)) & (jint) 0xFF), r);
  for (jint i = (JreLShift32(LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_SIZE, 3)) - 2; i >= 0; --i) {
    LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_multiplyX8WithLongArray_withLongArray_(r, r);
    LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_addWithLongArray_withLongArray_withLongArray_(IOSObjectArray_Get(nil_chk(T_), (jint) (JreURShift64(IOSLongArray_Get(z, JreURShift32(i, 3)), (JreLShift32((i & 7), 3)))) & (jint) 0xFF), r, r);
  }
  LibOrgBouncycastleCryptoModesKgcmKGCMUtil_128_copy__WithLongArray_withLongArray_(r, z);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLongArray:);
  methods[2].selector = @selector(multiplyHWithLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "T_", "[[J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "[J", "multiplyH" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128 = { "Tables4kKGCMMultiplier_128", "lib.org.bouncycastle.crypto.modes.kgcm", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128;
}

@end

void LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128_init(LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128 *new_LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128, init)
}

LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128 *create_LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesKgcmTables4kKGCMMultiplier_128)
