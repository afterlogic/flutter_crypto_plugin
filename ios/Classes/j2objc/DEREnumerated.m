//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DEREnumerated.java
//

#include "ASN1Enumerated.h"
#include "DEREnumerated.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleAsn1DEREnumerated

- (instancetype)initWithByteArray:(IOSByteArray *)bytes {
  LibOrgBouncycastleAsn1DEREnumerated_initWithByteArray_(self, bytes);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)value {
  LibOrgBouncycastleAsn1DEREnumerated_initWithJavaMathBigInteger_(self, value);
  return self;
}

- (instancetype)initWithInt:(jint)value {
  LibOrgBouncycastleAsn1DEREnumerated_initWithInt_(self, value);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithJavaMathBigInteger:);
  methods[2].selector = @selector(initWithInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "[B", "LJavaMathBigInteger;", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DEREnumerated = { "DEREnumerated", "lib.org.bouncycastle.asn1", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DEREnumerated;
}

@end

void LibOrgBouncycastleAsn1DEREnumerated_initWithByteArray_(LibOrgBouncycastleAsn1DEREnumerated *self, IOSByteArray *bytes) {
  LibOrgBouncycastleAsn1ASN1Enumerated_initWithByteArray_(self, bytes);
}

LibOrgBouncycastleAsn1DEREnumerated *new_LibOrgBouncycastleAsn1DEREnumerated_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DEREnumerated, initWithByteArray_, bytes)
}

LibOrgBouncycastleAsn1DEREnumerated *create_LibOrgBouncycastleAsn1DEREnumerated_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DEREnumerated, initWithByteArray_, bytes)
}

void LibOrgBouncycastleAsn1DEREnumerated_initWithJavaMathBigInteger_(LibOrgBouncycastleAsn1DEREnumerated *self, JavaMathBigInteger *value) {
  LibOrgBouncycastleAsn1ASN1Enumerated_initWithJavaMathBigInteger_(self, value);
}

LibOrgBouncycastleAsn1DEREnumerated *new_LibOrgBouncycastleAsn1DEREnumerated_initWithJavaMathBigInteger_(JavaMathBigInteger *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DEREnumerated, initWithJavaMathBigInteger_, value)
}

LibOrgBouncycastleAsn1DEREnumerated *create_LibOrgBouncycastleAsn1DEREnumerated_initWithJavaMathBigInteger_(JavaMathBigInteger *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DEREnumerated, initWithJavaMathBigInteger_, value)
}

void LibOrgBouncycastleAsn1DEREnumerated_initWithInt_(LibOrgBouncycastleAsn1DEREnumerated *self, jint value) {
  LibOrgBouncycastleAsn1ASN1Enumerated_initWithInt_(self, value);
}

LibOrgBouncycastleAsn1DEREnumerated *new_LibOrgBouncycastleAsn1DEREnumerated_initWithInt_(jint value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DEREnumerated, initWithInt_, value)
}

LibOrgBouncycastleAsn1DEREnumerated *create_LibOrgBouncycastleAsn1DEREnumerated_initWithInt_(jint value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DEREnumerated, initWithInt_, value)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DEREnumerated)