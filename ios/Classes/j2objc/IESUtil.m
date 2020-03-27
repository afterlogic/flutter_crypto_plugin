//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/IESUtil.java
//

#include "BlockCipher.h"
#include "BufferedBlockCipher.h"
#include "IESParameterSpec.h"
#include "IESUtil.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleJceSpecIESParameterSpec *)guessParameterSpecWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)iesBlockCipher
                                                                                                   withByteArray:(IOSByteArray *)nonce {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_guessParameterSpecWithLibOrgBouncycastleCryptoBufferedBlockCipher_withByteArray_(iesBlockCipher, nonce);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJceSpecIESParameterSpec;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(guessParameterSpecWithLibOrgBouncycastleCryptoBufferedBlockCipher:withByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "guessParameterSpec", "LLibOrgBouncycastleCryptoBufferedBlockCipher;[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil = { "IESUtil", "lib.org.bouncycastle.jcajce.provider.asymmetric.util", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil, init)
}

LibOrgBouncycastleJceSpecIESParameterSpec *LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_guessParameterSpecWithLibOrgBouncycastleCryptoBufferedBlockCipher_withByteArray_(LibOrgBouncycastleCryptoBufferedBlockCipher *iesBlockCipher, IOSByteArray *nonce) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil_initialize();
  if (iesBlockCipher == nil) {
    return new_LibOrgBouncycastleJceSpecIESParameterSpec_initWithByteArray_withByteArray_withInt_(nil, nil, 128);
  }
  else {
    id<LibOrgBouncycastleCryptoBlockCipher> underlyingCipher = [iesBlockCipher getUnderlyingCipher];
    if ([((NSString *) nil_chk([((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(underlyingCipher)) getAlgorithmName])) isEqual:@"DES"] || [((NSString *) nil_chk([underlyingCipher getAlgorithmName])) isEqual:@"RC2"] || [((NSString *) nil_chk([underlyingCipher getAlgorithmName])) isEqual:@"RC5-32"] || [((NSString *) nil_chk([underlyingCipher getAlgorithmName])) isEqual:@"RC5-64"]) {
      return new_LibOrgBouncycastleJceSpecIESParameterSpec_initWithByteArray_withByteArray_withInt_withInt_withByteArray_(nil, nil, 64, 64, nonce);
    }
    else if ([((NSString *) nil_chk([underlyingCipher getAlgorithmName])) isEqual:@"SKIPJACK"]) {
      return new_LibOrgBouncycastleJceSpecIESParameterSpec_initWithByteArray_withByteArray_withInt_withInt_withByteArray_(nil, nil, 80, 80, nonce);
    }
    else if ([((NSString *) nil_chk([underlyingCipher getAlgorithmName])) isEqual:@"GOST28147"]) {
      return new_LibOrgBouncycastleJceSpecIESParameterSpec_initWithByteArray_withByteArray_withInt_withInt_withByteArray_(nil, nil, 256, 256, nonce);
    }
    return new_LibOrgBouncycastleJceSpecIESParameterSpec_initWithByteArray_withByteArray_withInt_withInt_withByteArray_(nil, nil, 128, 128, nonce);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricUtilIESUtil)
