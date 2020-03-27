//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/OCSPResponseStatus.java
//

#include "ASN1Enumerated.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "J2ObjC_source.h"
#include "OCSPResponseStatus.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1OcspOCSPResponseStatus () {
 @public
  LibOrgBouncycastleAsn1ASN1Enumerated *value_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Enumerated:(LibOrgBouncycastleAsn1ASN1Enumerated *)value;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, value_, LibOrgBouncycastleAsn1ASN1Enumerated *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1OcspOCSPResponseStatus *self, LibOrgBouncycastleAsn1ASN1Enumerated *value);

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspOCSPResponseStatus *new_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspOCSPResponseStatus *create_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value);

@implementation LibOrgBouncycastleAsn1OcspOCSPResponseStatus

+ (jint)SUCCESSFUL {
  return LibOrgBouncycastleAsn1OcspOCSPResponseStatus_SUCCESSFUL;
}

+ (jint)MALFORMED_REQUEST {
  return LibOrgBouncycastleAsn1OcspOCSPResponseStatus_MALFORMED_REQUEST;
}

+ (jint)INTERNAL_ERROR {
  return LibOrgBouncycastleAsn1OcspOCSPResponseStatus_INTERNAL_ERROR;
}

+ (jint)TRY_LATER {
  return LibOrgBouncycastleAsn1OcspOCSPResponseStatus_TRY_LATER;
}

+ (jint)SIG_REQUIRED {
  return LibOrgBouncycastleAsn1OcspOCSPResponseStatus_SIG_REQUIRED;
}

+ (jint)UNAUTHORIZED {
  return LibOrgBouncycastleAsn1OcspOCSPResponseStatus_UNAUTHORIZED;
}

- (instancetype)initWithInt:(jint)value {
  LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithInt_(self, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Enumerated:(LibOrgBouncycastleAsn1ASN1Enumerated *)value {
  LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(self, value);
  return self;
}

+ (LibOrgBouncycastleAsn1OcspOCSPResponseStatus *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1OcspOCSPResponseStatus_getInstanceWithId_(obj);
}

- (JavaMathBigInteger *)getValue {
  return [((LibOrgBouncycastleAsn1ASN1Enumerated *) nil_chk(value_)) getValue];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return value_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspOCSPResponseStatus;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Enumerated:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getValue);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SUCCESSFUL", "I", .constantValue.asInt = LibOrgBouncycastleAsn1OcspOCSPResponseStatus_SUCCESSFUL, 0x19, -1, -1, -1, -1 },
    { "MALFORMED_REQUEST", "I", .constantValue.asInt = LibOrgBouncycastleAsn1OcspOCSPResponseStatus_MALFORMED_REQUEST, 0x19, -1, -1, -1, -1 },
    { "INTERNAL_ERROR", "I", .constantValue.asInt = LibOrgBouncycastleAsn1OcspOCSPResponseStatus_INTERNAL_ERROR, 0x19, -1, -1, -1, -1 },
    { "TRY_LATER", "I", .constantValue.asInt = LibOrgBouncycastleAsn1OcspOCSPResponseStatus_TRY_LATER, 0x19, -1, -1, -1, -1 },
    { "SIG_REQUIRED", "I", .constantValue.asInt = LibOrgBouncycastleAsn1OcspOCSPResponseStatus_SIG_REQUIRED, 0x19, -1, -1, -1, -1 },
    { "UNAUTHORIZED", "I", .constantValue.asInt = LibOrgBouncycastleAsn1OcspOCSPResponseStatus_UNAUTHORIZED, 0x19, -1, -1, -1, -1 },
    { "value_", "LLibOrgBouncycastleAsn1ASN1Enumerated;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "LLibOrgBouncycastleAsn1ASN1Enumerated;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1OcspOCSPResponseStatus = { "OCSPResponseStatus", "lib.org.bouncycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 5, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1OcspOCSPResponseStatus;
}

@end

void LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithInt_(LibOrgBouncycastleAsn1OcspOCSPResponseStatus *self, jint value) {
  LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(self, new_LibOrgBouncycastleAsn1ASN1Enumerated_initWithInt_(value));
}

LibOrgBouncycastleAsn1OcspOCSPResponseStatus *new_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithInt_(jint value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, initWithInt_, value)
}

LibOrgBouncycastleAsn1OcspOCSPResponseStatus *create_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithInt_(jint value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, initWithInt_, value)
}

void LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1OcspOCSPResponseStatus *self, LibOrgBouncycastleAsn1ASN1Enumerated *value) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->value_ = value;
}

LibOrgBouncycastleAsn1OcspOCSPResponseStatus *new_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, initWithLibOrgBouncycastleAsn1ASN1Enumerated_, value)
}

LibOrgBouncycastleAsn1OcspOCSPResponseStatus *create_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, initWithLibOrgBouncycastleAsn1ASN1Enumerated_, value)
}

LibOrgBouncycastleAsn1OcspOCSPResponseStatus *LibOrgBouncycastleAsn1OcspOCSPResponseStatus_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1OcspOCSPResponseStatus class]]) {
    return (LibOrgBouncycastleAsn1OcspOCSPResponseStatus *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1OcspOCSPResponseStatus)