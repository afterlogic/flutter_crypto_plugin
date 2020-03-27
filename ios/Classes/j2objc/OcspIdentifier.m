//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/OcspIdentifier.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "OcspIdentifier.h"
#include "ResponderID.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1EsfOcspIdentifier () {
 @public
  LibOrgBouncycastleAsn1OcspResponderID *ocspResponderID_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *producedAt_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfOcspIdentifier, ocspResponderID_, LibOrgBouncycastleAsn1OcspResponderID *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfOcspIdentifier, producedAt_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfOcspIdentifier *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfOcspIdentifier *new_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfOcspIdentifier *create_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EsfOcspIdentifier

+ (LibOrgBouncycastleAsn1EsfOcspIdentifier *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfOcspIdentifier_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1OcspResponderID:(LibOrgBouncycastleAsn1OcspResponderID *)ocspResponderID
                withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)producedAt {
  LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(self, ocspResponderID, producedAt);
  return self;
}

- (LibOrgBouncycastleAsn1OcspResponderID *)getOcspResponderID {
  return self->ocspResponderID_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getProducedAt {
  return self->producedAt_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->ocspResponderID_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->producedAt_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EsfOcspIdentifier;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspResponderID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1OcspResponderID:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:);
  methods[3].selector = @selector(getOcspResponderID);
  methods[4].selector = @selector(getProducedAt);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ocspResponderID_", "LLibOrgBouncycastleAsn1OcspResponderID;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "producedAt_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1OcspResponderID;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfOcspIdentifier = { "OcspIdentifier", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfOcspIdentifier;
}

@end

LibOrgBouncycastleAsn1EsfOcspIdentifier *LibOrgBouncycastleAsn1EsfOcspIdentifier_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfOcspIdentifier_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EsfOcspIdentifier class]]) {
    return (LibOrgBouncycastleAsn1EsfOcspIdentifier *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfOcspIdentifier *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->ocspResponderID_ = LibOrgBouncycastleAsn1OcspResponderID_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->producedAt_ = (LibOrgBouncycastleAsn1ASN1GeneralizedTime *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1GeneralizedTime class]);
}

LibOrgBouncycastleAsn1EsfOcspIdentifier *new_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfOcspIdentifier, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfOcspIdentifier *create_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfOcspIdentifier, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1EsfOcspIdentifier *self, LibOrgBouncycastleAsn1OcspResponderID *ocspResponderID, LibOrgBouncycastleAsn1ASN1GeneralizedTime *producedAt) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->ocspResponderID_ = ocspResponderID;
  self->producedAt_ = producedAt;
}

LibOrgBouncycastleAsn1EsfOcspIdentifier *new_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1OcspResponderID *ocspResponderID, LibOrgBouncycastleAsn1ASN1GeneralizedTime *producedAt) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfOcspIdentifier, initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_, ocspResponderID, producedAt)
}

LibOrgBouncycastleAsn1EsfOcspIdentifier *create_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1OcspResponderID *ocspResponderID, LibOrgBouncycastleAsn1ASN1GeneralizedTime *producedAt) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfOcspIdentifier, initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_, ocspResponderID, producedAt)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfOcspIdentifier)
