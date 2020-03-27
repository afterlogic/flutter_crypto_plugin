//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/PBKDF2KeySpec.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "DERNull.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PBKDF2KeySpec.h"
#include "PKCSObjectIdentifiers.h"
#include "javax/crypto/spec/PBEKeySpec.h"

@interface LibOrgBouncycastleJcajceSpecPBKDF2KeySpec () {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *prf_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec, prf_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)

inline LibOrgBouncycastleAsn1X509AlgorithmIdentifier *LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_get_defaultPRF(void);
static LibOrgBouncycastleAsn1X509AlgorithmIdentifier *LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_defaultPRF;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec, defaultPRF, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec)

@implementation LibOrgBouncycastleJcajceSpecPBKDF2KeySpec

- (instancetype)initWithCharArray:(IOSCharArray *)password
                    withByteArray:(IOSByteArray *)salt
                          withInt:(jint)iterationCount
                          withInt:(jint)keySize
withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)prf {
  LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_initWithCharArray_withByteArray_withInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(self, password, salt, iterationCount, keySize, prf);
  return self;
}

- (jboolean)isDefaultPrf {
  return [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_defaultPRF)) isEqual:prf_];
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getPrf {
  return prf_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithCharArray:withByteArray:withInt:withInt:withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:);
  methods[1].selector = @selector(isDefaultPrf);
  methods[2].selector = @selector(getPrf);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "defaultPRF", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x1a, -1, 1, -1, -1 },
    { "prf_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[C[BIILLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", &LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_defaultPRF };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceSpecPBKDF2KeySpec = { "PBKDF2KeySpec", "lib.org.bouncycastle.jcajce.spec", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceSpecPBKDF2KeySpec;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceSpecPBKDF2KeySpec class]) {
    LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_defaultPRF = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_hmacWithSHA1), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE));
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec)
  }
}

@end

void LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_initWithCharArray_withByteArray_withInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec *self, IOSCharArray *password, IOSByteArray *salt, jint iterationCount, jint keySize, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *prf) {
  JavaxCryptoSpecPBEKeySpec_initWithCharArray_withByteArray_withInt_withInt_(self, password, salt, iterationCount, keySize);
  self->prf_ = prf;
}

LibOrgBouncycastleJcajceSpecPBKDF2KeySpec *new_LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_initWithCharArray_withByteArray_withInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(IOSCharArray *password, IOSByteArray *salt, jint iterationCount, jint keySize, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *prf) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec, initWithCharArray_withByteArray_withInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_, password, salt, iterationCount, keySize, prf)
}

LibOrgBouncycastleJcajceSpecPBKDF2KeySpec *create_LibOrgBouncycastleJcajceSpecPBKDF2KeySpec_initWithCharArray_withByteArray_withInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(IOSCharArray *password, IOSByteArray *salt, jint iterationCount, jint keySize, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *prf) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec, initWithCharArray_withByteArray_withInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_, password, salt, iterationCount, keySize, prf)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceSpecPBKDF2KeySpec)
