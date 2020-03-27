//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/sphincs/SPHINCSPublicKeyParameters.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SPHINCSKeyParameters.h"
#include "SPHINCSPublicKeyParameters.h"

@interface LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters () {
 @public
  IOSByteArray *keyData_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters, keyData_, IOSByteArray *)

@implementation LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters

- (instancetype)initWithByteArray:(IOSByteArray *)keyData {
  LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_(self, keyData);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)keyData
                     withNSString:(NSString *)treeDigest {
  LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_withNSString_(self, keyData, treeDigest);
  return self;
}

- (IOSByteArray *)getKeyData {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(keyData_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithByteArray:withNSString:);
  methods[2].selector = @selector(getKeyData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keyData_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "[BLNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters = { "SPHINCSPublicKeyParameters", "lib.org.bouncycastle.pqc.crypto.sphincs", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *self, IOSByteArray *keyData) {
  LibOrgBouncycastlePqcCryptoSphincsSPHINCSKeyParameters_initWithBoolean_withNSString_(self, false, nil);
  self->keyData_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(keyData);
}

LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_(IOSByteArray *keyData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters, initWithByteArray_, keyData)
}

LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_(IOSByteArray *keyData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters, initWithByteArray_, keyData)
}

void LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_withNSString_(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *self, IOSByteArray *keyData, NSString *treeDigest) {
  LibOrgBouncycastlePqcCryptoSphincsSPHINCSKeyParameters_initWithBoolean_withNSString_(self, false, treeDigest);
  self->keyData_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(keyData);
}

LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_withNSString_(IOSByteArray *keyData, NSString *treeDigest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters, initWithByteArray_withNSString_, keyData, treeDigest)
}

LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters_initWithByteArray_withNSString_(IOSByteArray *keyData, NSString *treeDigest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters, initWithByteArray_withNSString_, keyData, treeDigest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters)
