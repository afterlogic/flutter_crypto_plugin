//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/ECGOST3410Parameters.java
//

#include "ASN1ObjectIdentifier.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECGOST3410Parameters.h"
#include "ECNamedDomainParameters.h"
#include "ECPoint.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoParamsECGOST3410Parameters () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet_;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet_;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsECGOST3410Parameters, publicKeyParamSet_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsECGOST3410Parameters, digestParamSet_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsECGOST3410Parameters, encryptionParamSet_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

@implementation LibOrgBouncycastleCryptoParamsECGOST3410Parameters

- (instancetype)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)ecParameters
                          withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)publicKeyParamSet
                          withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestParamSet {
  LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, ecParameters, publicKeyParamSet, digestParamSet);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)ecParameters
                          withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)publicKeyParamSet
                          withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestParamSet
                          withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)encryptionParamSet {
  LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, ecParameters, publicKeyParamSet, digestParamSet, encryptionParamSet);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getPublicKeyParamSet {
  return publicKeyParamSet_;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getDigestParamSet {
  return digestParamSet_;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getEncryptionParamSet {
  return encryptionParamSet_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsECDomainParameters:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoParamsECDomainParameters:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[2].selector = @selector(getPublicKeyParamSet);
  methods[3].selector = @selector(getDigestParamSet);
  methods[4].selector = @selector(getEncryptionParamSet);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "publicKeyParamSet_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "digestParamSet_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "encryptionParamSet_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsECDomainParameters;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleCryptoParamsECDomainParameters;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsECGOST3410Parameters = { "ECGOST3410Parameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsECGOST3410Parameters;
}

@end

void LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleCryptoParamsECGOST3410Parameters *self, LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet) {
  LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, ecParameters, publicKeyParamSet, digestParamSet, nil);
}

LibOrgBouncycastleCryptoParamsECGOST3410Parameters *new_LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsECGOST3410Parameters, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, ecParameters, publicKeyParamSet, digestParamSet)
}

LibOrgBouncycastleCryptoParamsECGOST3410Parameters *create_LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsECGOST3410Parameters, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, ecParameters, publicKeyParamSet, digestParamSet)
}

void LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleCryptoParamsECGOST3410Parameters *self, LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet) {
  LibOrgBouncycastleCryptoParamsECNamedDomainParameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(self, publicKeyParamSet, [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(ecParameters)) getCurve], [ecParameters getG], [ecParameters getN], [ecParameters getH], [ecParameters getSeed]);
  if ([ecParameters isKindOfClass:[LibOrgBouncycastleCryptoParamsECNamedDomainParameters class]]) {
    if (![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(publicKeyParamSet)) isEqual:[((LibOrgBouncycastleCryptoParamsECNamedDomainParameters *) ecParameters) getName]]) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"named parameters do not match publicKeyParamSet value");
    }
  }
  self->publicKeyParamSet_ = publicKeyParamSet;
  self->digestParamSet_ = digestParamSet;
  self->encryptionParamSet_ = encryptionParamSet;
}

LibOrgBouncycastleCryptoParamsECGOST3410Parameters *new_LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsECGOST3410Parameters, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, ecParameters, publicKeyParamSet, digestParamSet, encryptionParamSet)
}

LibOrgBouncycastleCryptoParamsECGOST3410Parameters *create_LibOrgBouncycastleCryptoParamsECGOST3410Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *publicKeyParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestParamSet, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionParamSet) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsECGOST3410Parameters, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, ecParameters, publicKeyParamSet, digestParamSet, encryptionParamSet)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsECGOST3410Parameters)