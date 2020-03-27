//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/QTESLAPublicKeyParameters.java
//

#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "QTESLAPublicKeyParameters.h"
#include "QTESLASecurityCategory.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters () {
 @public
  jint securityCategory_;
  IOSByteArray *publicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters, publicKey_, IOSByteArray *)

@implementation LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters

- (instancetype)initWithInt:(jint)securityCategory
              withByteArray:(IOSByteArray *)publicKey {
  LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters_initWithInt_withByteArray_(self, securityCategory, publicKey);
  return self;
}

- (jint)getSecurityCategory {
  return self->securityCategory_;
}

- (IOSByteArray *)getPublicData {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(publicKey_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withByteArray:);
  methods[1].selector = @selector(getSecurityCategory);
  methods[2].selector = @selector(getPublicData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "securityCategory_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKey_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters = { "QTESLAPublicKeyParameters", "lib.org.bouncycastle.pqc.crypto.qtesla", ptrTable, methods, fields, 7, 0x11, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters_initWithInt_withByteArray_(LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters *self, jint securityCategory, IOSByteArray *publicKey) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, false);
  if (((IOSByteArray *) nil_chk(publicKey))->size_ != LibOrgBouncycastlePqcCryptoQteslaQTESLASecurityCategory_getPublicSizeWithInt_(securityCategory)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid key size for security category");
  }
  self->securityCategory_ = securityCategory;
  self->publicKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(publicKey);
}

LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters_initWithInt_withByteArray_(jint securityCategory, IOSByteArray *publicKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters, initWithInt_withByteArray_, securityCategory, publicKey)
}

LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters_initWithInt_withByteArray_(jint securityCategory, IOSByteArray *publicKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters, initWithInt_withByteArray_, securityCategory, publicKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters)
