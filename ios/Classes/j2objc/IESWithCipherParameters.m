//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/IESWithCipherParameters.java
//

#include "IESParameters.h"
#include "IESWithCipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoParamsIESWithCipherParameters () {
 @public
  jint cipherKeySize_;
}

@end

@implementation LibOrgBouncycastleCryptoParamsIESWithCipherParameters

- (instancetype)initWithByteArray:(IOSByteArray *)derivation
                    withByteArray:(IOSByteArray *)encoding
                          withInt:(jint)macKeySize
                          withInt:(jint)cipherKeySize {
  LibOrgBouncycastleCryptoParamsIESWithCipherParameters_initWithByteArray_withByteArray_withInt_withInt_(self, derivation, encoding, macKeySize, cipherKeySize);
  return self;
}

- (jint)getCipherKeySize {
  return cipherKeySize_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withByteArray:withInt:withInt:);
  methods[1].selector = @selector(getCipherKeySize);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cipherKeySize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B[BII" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsIESWithCipherParameters = { "IESWithCipherParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsIESWithCipherParameters;
}

@end

void LibOrgBouncycastleCryptoParamsIESWithCipherParameters_initWithByteArray_withByteArray_withInt_withInt_(LibOrgBouncycastleCryptoParamsIESWithCipherParameters *self, IOSByteArray *derivation, IOSByteArray *encoding, jint macKeySize, jint cipherKeySize) {
  LibOrgBouncycastleCryptoParamsIESParameters_initWithByteArray_withByteArray_withInt_(self, derivation, encoding, macKeySize);
  self->cipherKeySize_ = cipherKeySize;
}

LibOrgBouncycastleCryptoParamsIESWithCipherParameters *new_LibOrgBouncycastleCryptoParamsIESWithCipherParameters_initWithByteArray_withByteArray_withInt_withInt_(IOSByteArray *derivation, IOSByteArray *encoding, jint macKeySize, jint cipherKeySize) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsIESWithCipherParameters, initWithByteArray_withByteArray_withInt_withInt_, derivation, encoding, macKeySize, cipherKeySize)
}

LibOrgBouncycastleCryptoParamsIESWithCipherParameters *create_LibOrgBouncycastleCryptoParamsIESWithCipherParameters_initWithByteArray_withByteArray_withInt_withInt_(IOSByteArray *derivation, IOSByteArray *encoding, jint macKeySize, jint cipherKeySize) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsIESWithCipherParameters, initWithByteArray_withByteArray_withInt_withInt_, derivation, encoding, macKeySize, cipherKeySize)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsIESWithCipherParameters)
