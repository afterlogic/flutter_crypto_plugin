//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/KeyAgreeRecipientIdentifier.java
//

#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Asn1CmsIssuerAndSerialNumber.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "KeyAgreeRecipientIdentifier.h"
#include "RecipientKeyIdentifier.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier () {
 @public
  LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerSerial_;
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *rKeyID_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier, issuerSerial_, LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier, rKeyID_, LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *)

@implementation LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier

+ (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                    withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber:(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)issuerSerial {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(self, issuerSerial);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier:(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *)rKeyID {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(self, rKeyID);
  return self;
}

- (LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)getIssuerAndSerialNumber {
  return issuerSerial_;
}

- (LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *)getRKeyID {
  return rKeyID_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (issuerSerial_ != nil) {
    return [issuerSerial_ toASN1Primitive];
  }
  return new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, rKeyID_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier:);
  methods[4].selector = @selector(getIssuerAndSerialNumber);
  methods[5].selector = @selector(getRKeyID);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "issuerSerial_", "LLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "rKeyID_", "LLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber;", "LLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier = { "KeyAgreeRecipientIdentifier", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier;
}

@end

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initialize();
  return LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier class]]) {
    return (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *) cast_chk(obj, [LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_getInstanceWithId_(obj));
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]] && [((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk(obj, [LibOrgBouncycastleAsn1ASN1TaggedObject class])) getTagNo] == 0) {
    return new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk(obj, [LibOrgBouncycastleAsn1ASN1TaggedObject class]), false));
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid KeyAgreeRecipientIdentifier: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *self, LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerSerial) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->issuerSerial_ = issuerSerial;
  self->rKeyID_ = nil;
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerSerial) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier, initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_, issuerSerial)
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *create_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerSerial) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier, initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_, issuerSerial)
}

void LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *self, LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *rKeyID) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->issuerSerial_ = nil;
  self->rKeyID_ = rKeyID;
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *rKeyID) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier, initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_, rKeyID)
}

LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *create_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *rKeyID) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier, initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_, rKeyID)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier)
