//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/NamedCurve.java
//

#include "J2ObjC_source.h"
#include "NamedCurve.h"

@implementation LibOrgBouncycastleCryptoTlsNamedCurve

+ (jint)sect163k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect163k1;
}

+ (jint)sect163r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect163r1;
}

+ (jint)sect163r2 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect163r2;
}

+ (jint)sect193r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect193r1;
}

+ (jint)sect193r2 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect193r2;
}

+ (jint)sect233k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect233k1;
}

+ (jint)sect233r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect233r1;
}

+ (jint)sect239k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect239k1;
}

+ (jint)sect283k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect283k1;
}

+ (jint)sect283r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect283r1;
}

+ (jint)sect409k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect409k1;
}

+ (jint)sect409r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect409r1;
}

+ (jint)sect571k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect571k1;
}

+ (jint)sect571r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_sect571r1;
}

+ (jint)secp160k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp160k1;
}

+ (jint)secp160r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp160r1;
}

+ (jint)secp160r2 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp160r2;
}

+ (jint)secp192k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp192k1;
}

+ (jint)secp192r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp192r1;
}

+ (jint)secp224k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp224k1;
}

+ (jint)secp224r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp224r1;
}

+ (jint)secp256k1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp256k1;
}

+ (jint)secp256r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp256r1;
}

+ (jint)secp384r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp384r1;
}

+ (jint)secp521r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_secp521r1;
}

+ (jint)brainpoolP256r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_brainpoolP256r1;
}

+ (jint)brainpoolP384r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_brainpoolP384r1;
}

+ (jint)brainpoolP512r1 {
  return LibOrgBouncycastleCryptoTlsNamedCurve_brainpoolP512r1;
}

+ (jint)arbitrary_explicit_prime_curves {
  return LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_prime_curves;
}

+ (jint)arbitrary_explicit_char2_curves {
  return LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_char2_curves;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsNamedCurve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isValidWithInt:(jint)namedCurve {
  return LibOrgBouncycastleCryptoTlsNamedCurve_isValidWithInt_(namedCurve);
}

+ (jboolean)refersToASpecificNamedCurveWithInt:(jint)namedCurve {
  return LibOrgBouncycastleCryptoTlsNamedCurve_refersToASpecificNamedCurveWithInt_(namedCurve);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isValidWithInt:);
  methods[2].selector = @selector(refersToASpecificNamedCurveWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "sect163k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect163k1, 0x19, -1, -1, -1, -1 },
    { "sect163r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect163r1, 0x19, -1, -1, -1, -1 },
    { "sect163r2", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect163r2, 0x19, -1, -1, -1, -1 },
    { "sect193r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect193r1, 0x19, -1, -1, -1, -1 },
    { "sect193r2", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect193r2, 0x19, -1, -1, -1, -1 },
    { "sect233k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect233k1, 0x19, -1, -1, -1, -1 },
    { "sect233r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect233r1, 0x19, -1, -1, -1, -1 },
    { "sect239k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect239k1, 0x19, -1, -1, -1, -1 },
    { "sect283k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect283k1, 0x19, -1, -1, -1, -1 },
    { "sect283r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect283r1, 0x19, -1, -1, -1, -1 },
    { "sect409k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect409k1, 0x19, -1, -1, -1, -1 },
    { "sect409r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect409r1, 0x19, -1, -1, -1, -1 },
    { "sect571k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect571k1, 0x19, -1, -1, -1, -1 },
    { "sect571r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_sect571r1, 0x19, -1, -1, -1, -1 },
    { "secp160k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp160k1, 0x19, -1, -1, -1, -1 },
    { "secp160r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp160r1, 0x19, -1, -1, -1, -1 },
    { "secp160r2", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp160r2, 0x19, -1, -1, -1, -1 },
    { "secp192k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp192k1, 0x19, -1, -1, -1, -1 },
    { "secp192r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp192r1, 0x19, -1, -1, -1, -1 },
    { "secp224k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp224k1, 0x19, -1, -1, -1, -1 },
    { "secp224r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp224r1, 0x19, -1, -1, -1, -1 },
    { "secp256k1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp256k1, 0x19, -1, -1, -1, -1 },
    { "secp256r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp256r1, 0x19, -1, -1, -1, -1 },
    { "secp384r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp384r1, 0x19, -1, -1, -1, -1 },
    { "secp521r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_secp521r1, 0x19, -1, -1, -1, -1 },
    { "brainpoolP256r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_brainpoolP256r1, 0x19, -1, -1, -1, -1 },
    { "brainpoolP384r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_brainpoolP384r1, 0x19, -1, -1, -1, -1 },
    { "brainpoolP512r1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_brainpoolP512r1, 0x19, -1, -1, -1, -1 },
    { "arbitrary_explicit_prime_curves", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_prime_curves, 0x19, -1, -1, -1, -1 },
    { "arbitrary_explicit_char2_curves", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_char2_curves, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isValid", "I", "refersToASpecificNamedCurve" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsNamedCurve = { "NamedCurve", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 3, 30, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsNamedCurve;
}

@end

void LibOrgBouncycastleCryptoTlsNamedCurve_init(LibOrgBouncycastleCryptoTlsNamedCurve *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsNamedCurve *new_LibOrgBouncycastleCryptoTlsNamedCurve_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsNamedCurve, init)
}

LibOrgBouncycastleCryptoTlsNamedCurve *create_LibOrgBouncycastleCryptoTlsNamedCurve_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsNamedCurve, init)
}

jboolean LibOrgBouncycastleCryptoTlsNamedCurve_isValidWithInt_(jint namedCurve) {
  LibOrgBouncycastleCryptoTlsNamedCurve_initialize();
  return (namedCurve >= LibOrgBouncycastleCryptoTlsNamedCurve_sect163k1 && namedCurve <= LibOrgBouncycastleCryptoTlsNamedCurve_brainpoolP512r1) || (namedCurve >= LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_prime_curves && namedCurve <= LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_char2_curves);
}

jboolean LibOrgBouncycastleCryptoTlsNamedCurve_refersToASpecificNamedCurveWithInt_(jint namedCurve) {
  LibOrgBouncycastleCryptoTlsNamedCurve_initialize();
  switch (namedCurve) {
    case LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_prime_curves:
    case LibOrgBouncycastleCryptoTlsNamedCurve_arbitrary_explicit_char2_curves:
    return false;
    default:
    return true;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsNamedCurve)
