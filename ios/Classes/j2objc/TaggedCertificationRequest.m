//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/TaggedCertificationRequest.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "BodyPartID.h"
#include "CmcCertificationRequest.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "TaggedCertificationRequest.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcTaggedCertificationRequest () {
 @public
  LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID_;
  LibOrgBouncycastleAsn1CmcCmcCertificationRequest *certificationRequest_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest, bodyPartID_, LibOrgBouncycastleAsn1CmcBodyPartID *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest, certificationRequest_, LibOrgBouncycastleAsn1CmcCmcCertificationRequest *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *new_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *create_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmcTaggedCertificationRequest

- (instancetype)initWithLibOrgBouncycastleAsn1CmcBodyPartID:(LibOrgBouncycastleAsn1CmcBodyPartID *)bodyPartID
       withLibOrgBouncycastleAsn1CmcCmcCertificationRequest:(LibOrgBouncycastleAsn1CmcCmcCertificationRequest *)certificationRequest {
  LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmcCmcCertificationRequest_(self, bodyPartID, certificationRequest);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_getInstanceWithId_(o);
}

+ (LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                   withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:bodyPartID_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certificationRequest_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcTaggedCertificationRequest;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcTaggedCertificationRequest;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmcBodyPartID:withLibOrgBouncycastleAsn1CmcCmcCertificationRequest:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyPartID_", "LLibOrgBouncycastleAsn1CmcBodyPartID;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "certificationRequest_", "LLibOrgBouncycastleAsn1CmcCmcCertificationRequest;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmcBodyPartID;LLibOrgBouncycastleAsn1CmcCmcCertificationRequest;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcTaggedCertificationRequest = { "TaggedCertificationRequest", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest;
}

@end

void LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmcCmcCertificationRequest_(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *self, LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmcCmcCertificationRequest *certificationRequest) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->bodyPartID_ = bodyPartID;
  self->certificationRequest_ = certificationRequest;
}

LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *new_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmcCmcCertificationRequest_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmcCmcCertificationRequest *certificationRequest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest, initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmcCmcCertificationRequest_, bodyPartID, certificationRequest)
}

LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *create_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmcCmcCertificationRequest_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmcCmcCertificationRequest *certificationRequest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest, initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmcCmcCertificationRequest_, bodyPartID, certificationRequest)
}

void LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->bodyPartID_ = LibOrgBouncycastleAsn1CmcBodyPartID_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->certificationRequest_ = LibOrgBouncycastleAsn1CmcCmcCertificationRequest_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *new_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *create_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmcTaggedCertificationRequest class]]) {
    return (LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_initialize();
  return LibOrgBouncycastleAsn1CmcTaggedCertificationRequest_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest)