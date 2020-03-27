//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/DHPublicKey.java
//

#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "DHPublicKey.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1X9DHPublicKey () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *y_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)y;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9DHPublicKey, y_, LibOrgBouncycastleAsn1ASN1Integer *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X9DHPublicKey *self, LibOrgBouncycastleAsn1ASN1Integer *y);

__attribute__((unused)) static LibOrgBouncycastleAsn1X9DHPublicKey *new_LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *y) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X9DHPublicKey *create_LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *y);

@implementation LibOrgBouncycastleAsn1X9DHPublicKey

+ (LibOrgBouncycastleAsn1X9DHPublicKey *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                   withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X9DHPublicKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X9DHPublicKey *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X9DHPublicKey_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)y {
  LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_(self, y);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)y {
  LibOrgBouncycastleAsn1X9DHPublicKey_initWithJavaMathBigInteger_(self, y);
  return self;
}

- (JavaMathBigInteger *)getY {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->y_)) getPositiveValue];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return self->y_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X9DHPublicKey;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9DHPublicKey;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:);
  methods[3].selector = @selector(initWithJavaMathBigInteger:);
  methods[4].selector = @selector(getY);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "y_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Integer;", "LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X9DHPublicKey = { "DHPublicKey", "lib.org.bouncycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X9DHPublicKey;
}

@end

LibOrgBouncycastleAsn1X9DHPublicKey *LibOrgBouncycastleAsn1X9DHPublicKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X9DHPublicKey_initialize();
  return LibOrgBouncycastleAsn1X9DHPublicKey_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X9DHPublicKey *LibOrgBouncycastleAsn1X9DHPublicKey_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X9DHPublicKey_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1X9DHPublicKey class]]) {
    return (LibOrgBouncycastleAsn1X9DHPublicKey *) cast_chk(obj, [LibOrgBouncycastleAsn1X9DHPublicKey class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
    return new_LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_((LibOrgBouncycastleAsn1ASN1Integer *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid DHPublicKey: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X9DHPublicKey *self, LibOrgBouncycastleAsn1ASN1Integer *y) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (y == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'y' cannot be null");
  }
  self->y_ = y;
}

LibOrgBouncycastleAsn1X9DHPublicKey *new_LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *y) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9DHPublicKey, initWithLibOrgBouncycastleAsn1ASN1Integer_, y)
}

LibOrgBouncycastleAsn1X9DHPublicKey *create_LibOrgBouncycastleAsn1X9DHPublicKey_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *y) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9DHPublicKey, initWithLibOrgBouncycastleAsn1ASN1Integer_, y)
}

void LibOrgBouncycastleAsn1X9DHPublicKey_initWithJavaMathBigInteger_(LibOrgBouncycastleAsn1X9DHPublicKey *self, JavaMathBigInteger *y) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (y == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'y' cannot be null");
  }
  self->y_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(y);
}

LibOrgBouncycastleAsn1X9DHPublicKey *new_LibOrgBouncycastleAsn1X9DHPublicKey_initWithJavaMathBigInteger_(JavaMathBigInteger *y) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9DHPublicKey, initWithJavaMathBigInteger_, y)
}

LibOrgBouncycastleAsn1X9DHPublicKey *create_LibOrgBouncycastleAsn1X9DHPublicKey_initWithJavaMathBigInteger_(JavaMathBigInteger *y) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9DHPublicKey, initWithJavaMathBigInteger_, y)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X9DHPublicKey)
