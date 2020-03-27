//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/ServiceType.java
//

#include "ASN1Enumerated.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "J2ObjC_source.h"
#include "ServiceType.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1DvcsServiceType () {
 @public
  LibOrgBouncycastleAsn1ASN1Enumerated *value_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Enumerated:(LibOrgBouncycastleAsn1ASN1Enumerated *)value;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsServiceType, value_, LibOrgBouncycastleAsn1ASN1Enumerated *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1DvcsServiceType *self, LibOrgBouncycastleAsn1ASN1Enumerated *value);

__attribute__((unused)) static LibOrgBouncycastleAsn1DvcsServiceType *new_LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1DvcsServiceType *create_LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1DvcsServiceType)

LibOrgBouncycastleAsn1DvcsServiceType *LibOrgBouncycastleAsn1DvcsServiceType_CPD;
LibOrgBouncycastleAsn1DvcsServiceType *LibOrgBouncycastleAsn1DvcsServiceType_VSD;
LibOrgBouncycastleAsn1DvcsServiceType *LibOrgBouncycastleAsn1DvcsServiceType_VPKC;
LibOrgBouncycastleAsn1DvcsServiceType *LibOrgBouncycastleAsn1DvcsServiceType_CCPD;

@implementation LibOrgBouncycastleAsn1DvcsServiceType

+ (LibOrgBouncycastleAsn1DvcsServiceType *)CPD {
  return LibOrgBouncycastleAsn1DvcsServiceType_CPD;
}

+ (LibOrgBouncycastleAsn1DvcsServiceType *)VSD {
  return LibOrgBouncycastleAsn1DvcsServiceType_VSD;
}

+ (LibOrgBouncycastleAsn1DvcsServiceType *)VPKC {
  return LibOrgBouncycastleAsn1DvcsServiceType_VPKC;
}

+ (LibOrgBouncycastleAsn1DvcsServiceType *)CCPD {
  return LibOrgBouncycastleAsn1DvcsServiceType_CCPD;
}

- (instancetype)initWithInt:(jint)value {
  LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(self, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Enumerated:(LibOrgBouncycastleAsn1ASN1Enumerated *)value {
  LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(self, value);
  return self;
}

+ (LibOrgBouncycastleAsn1DvcsServiceType *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1DvcsServiceType_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1DvcsServiceType *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                     withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1DvcsServiceType_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (JavaMathBigInteger *)getValue {
  return [((LibOrgBouncycastleAsn1ASN1Enumerated *) nil_chk(value_)) getValue];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return value_;
}

- (NSString *)description {
  jint num = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Enumerated *) nil_chk(value_)) getValue])) intValue];
  return JreStrcat("I$", num, (num == [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1DvcsServiceType *) nil_chk(LibOrgBouncycastleAsn1DvcsServiceType_CPD)) getValue])) intValue] ? @"(CPD)" : num == [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1DvcsServiceType *) nil_chk(LibOrgBouncycastleAsn1DvcsServiceType_VSD)) getValue])) intValue] ? @"(VSD)" : num == [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1DvcsServiceType *) nil_chk(LibOrgBouncycastleAsn1DvcsServiceType_VPKC)) getValue])) intValue] ? @"(VPKC)" : num == [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1DvcsServiceType *) nil_chk(LibOrgBouncycastleAsn1DvcsServiceType_CCPD)) getValue])) intValue] ? @"(CCPD)" : @"?"));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsServiceType;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsServiceType;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 5, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Enumerated:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(getValue);
  methods[5].selector = @selector(toASN1Primitive);
  methods[6].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "CPD", "LLibOrgBouncycastleAsn1DvcsServiceType;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
    { "VSD", "LLibOrgBouncycastleAsn1DvcsServiceType;", .constantValue.asLong = 0, 0x19, -1, 7, -1, -1 },
    { "VPKC", "LLibOrgBouncycastleAsn1DvcsServiceType;", .constantValue.asLong = 0, 0x19, -1, 8, -1, -1 },
    { "CCPD", "LLibOrgBouncycastleAsn1DvcsServiceType;", .constantValue.asLong = 0, 0x19, -1, 9, -1, -1 },
    { "value_", "LLibOrgBouncycastleAsn1ASN1Enumerated;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "LLibOrgBouncycastleAsn1ASN1Enumerated;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "toString", &LibOrgBouncycastleAsn1DvcsServiceType_CPD, &LibOrgBouncycastleAsn1DvcsServiceType_VSD, &LibOrgBouncycastleAsn1DvcsServiceType_VPKC, &LibOrgBouncycastleAsn1DvcsServiceType_CCPD };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DvcsServiceType = { "ServiceType", "lib.org.bouncycastle.asn1.dvcs", ptrTable, methods, fields, 7, 0x1, 7, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DvcsServiceType;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1DvcsServiceType class]) {
    LibOrgBouncycastleAsn1DvcsServiceType_CPD = new_LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(1);
    LibOrgBouncycastleAsn1DvcsServiceType_VSD = new_LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(2);
    LibOrgBouncycastleAsn1DvcsServiceType_VPKC = new_LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(3);
    LibOrgBouncycastleAsn1DvcsServiceType_CCPD = new_LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(4);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1DvcsServiceType)
  }
}

@end

void LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(LibOrgBouncycastleAsn1DvcsServiceType *self, jint value) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->value_ = new_LibOrgBouncycastleAsn1ASN1Enumerated_initWithInt_(value);
}

LibOrgBouncycastleAsn1DvcsServiceType *new_LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(jint value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DvcsServiceType, initWithInt_, value)
}

LibOrgBouncycastleAsn1DvcsServiceType *create_LibOrgBouncycastleAsn1DvcsServiceType_initWithInt_(jint value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DvcsServiceType, initWithInt_, value)
}

void LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1DvcsServiceType *self, LibOrgBouncycastleAsn1ASN1Enumerated *value) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->value_ = value;
}

LibOrgBouncycastleAsn1DvcsServiceType *new_LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DvcsServiceType, initWithLibOrgBouncycastleAsn1ASN1Enumerated_, value)
}

LibOrgBouncycastleAsn1DvcsServiceType *create_LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DvcsServiceType, initWithLibOrgBouncycastleAsn1ASN1Enumerated_, value)
}

LibOrgBouncycastleAsn1DvcsServiceType *LibOrgBouncycastleAsn1DvcsServiceType_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1DvcsServiceType_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1DvcsServiceType class]]) {
    return (LibOrgBouncycastleAsn1DvcsServiceType *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1DvcsServiceType_initWithLibOrgBouncycastleAsn1ASN1Enumerated_(LibOrgBouncycastleAsn1ASN1Enumerated_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1DvcsServiceType *LibOrgBouncycastleAsn1DvcsServiceType_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1DvcsServiceType_initialize();
  return LibOrgBouncycastleAsn1DvcsServiceType_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Enumerated_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DvcsServiceType)
