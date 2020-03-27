//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/SingleResponse.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Asn1OcspCertStatus.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "Extensions.h"
#include "J2ObjC_source.h"
#include "OcspCertID.h"
#include "SingleResponse.h"
#include "X509Extensions.h"

@interface LibOrgBouncycastleAsn1OcspSingleResponse () {
 @public
  LibOrgBouncycastleAsn1OcspOcspCertID *certID_;
  LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *certStatus_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *thisUpdate_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *nextUpdate_;
  LibOrgBouncycastleAsn1X509Extensions *singleExtensions_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspSingleResponse, certID_, LibOrgBouncycastleAsn1OcspOcspCertID *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspSingleResponse, certStatus_, LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspSingleResponse, thisUpdate_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspSingleResponse, nextUpdate_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspSingleResponse, singleExtensions_, LibOrgBouncycastleAsn1X509Extensions *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspSingleResponse *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspSingleResponse *new_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspSingleResponse *create_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1OcspSingleResponse

- (instancetype)initWithLibOrgBouncycastleAsn1OcspOcspCertID:(LibOrgBouncycastleAsn1OcspOcspCertID *)certID
            withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus:(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *)certStatus
               withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)thisUpdate
               withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)nextUpdate
                withLibOrgBouncycastleAsn1X509X509Extensions:(LibOrgBouncycastleAsn1X509X509Extensions *)singleExtensions {
  LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509X509Extensions_(self, certID, certStatus, thisUpdate, nextUpdate, singleExtensions);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1OcspOcspCertID:(LibOrgBouncycastleAsn1OcspOcspCertID *)certID
            withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus:(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *)certStatus
               withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)thisUpdate
               withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)nextUpdate
                    withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)singleExtensions {
  LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509Extensions_(self, certID, certStatus, thisUpdate, nextUpdate, singleExtensions);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1OcspSingleResponse *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1OcspSingleResponse_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1OcspSingleResponse *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1OcspSingleResponse_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1OcspOcspCertID *)getCertID {
  return certID_;
}

- (LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *)getCertStatus {
  return certStatus_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getThisUpdate {
  return thisUpdate_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getNextUpdate {
  return nextUpdate_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getSingleExtensions {
  return singleExtensions_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certID_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certStatus_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:thisUpdate_];
  if (nextUpdate_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, nextUpdate_)];
  }
  if (singleExtensions_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 1, singleExtensions_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspSingleResponse;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspSingleResponse;", 0x9, 3, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspOcspCertID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1OcspOcspCertID:withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1X509X509Extensions:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1OcspOcspCertID:withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1X509Extensions:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getCertID);
  methods[6].selector = @selector(getCertStatus);
  methods[7].selector = @selector(getThisUpdate);
  methods[8].selector = @selector(getNextUpdate);
  methods[9].selector = @selector(getSingleExtensions);
  methods[10].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certID_", "LLibOrgBouncycastleAsn1OcspOcspCertID;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certStatus_", "LLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "thisUpdate_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nextUpdate_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "singleExtensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1OcspOcspCertID;LLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1X509X509Extensions;", "LLibOrgBouncycastleAsn1OcspOcspCertID;LLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1X509Extensions;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1OcspSingleResponse = { "SingleResponse", "lib.org.bouncycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 11, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1OcspSingleResponse;
}

@end

void LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509X509Extensions_(LibOrgBouncycastleAsn1OcspSingleResponse *self, LibOrgBouncycastleAsn1OcspOcspCertID *certID, LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *certStatus, LibOrgBouncycastleAsn1ASN1GeneralizedTime *thisUpdate, LibOrgBouncycastleAsn1ASN1GeneralizedTime *nextUpdate, LibOrgBouncycastleAsn1X509X509Extensions *singleExtensions) {
  LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509Extensions_(self, certID, certStatus, thisUpdate, nextUpdate, LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(singleExtensions));
}

LibOrgBouncycastleAsn1OcspSingleResponse *new_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509X509Extensions_(LibOrgBouncycastleAsn1OcspOcspCertID *certID, LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *certStatus, LibOrgBouncycastleAsn1ASN1GeneralizedTime *thisUpdate, LibOrgBouncycastleAsn1ASN1GeneralizedTime *nextUpdate, LibOrgBouncycastleAsn1X509X509Extensions *singleExtensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspSingleResponse, initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509X509Extensions_, certID, certStatus, thisUpdate, nextUpdate, singleExtensions)
}

LibOrgBouncycastleAsn1OcspSingleResponse *create_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509X509Extensions_(LibOrgBouncycastleAsn1OcspOcspCertID *certID, LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *certStatus, LibOrgBouncycastleAsn1ASN1GeneralizedTime *thisUpdate, LibOrgBouncycastleAsn1ASN1GeneralizedTime *nextUpdate, LibOrgBouncycastleAsn1X509X509Extensions *singleExtensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspSingleResponse, initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509X509Extensions_, certID, certStatus, thisUpdate, nextUpdate, singleExtensions)
}

void LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1OcspSingleResponse *self, LibOrgBouncycastleAsn1OcspOcspCertID *certID, LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *certStatus, LibOrgBouncycastleAsn1ASN1GeneralizedTime *thisUpdate, LibOrgBouncycastleAsn1ASN1GeneralizedTime *nextUpdate, LibOrgBouncycastleAsn1X509Extensions *singleExtensions) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certID_ = certID;
  self->certStatus_ = certStatus;
  self->thisUpdate_ = thisUpdate;
  self->nextUpdate_ = nextUpdate;
  self->singleExtensions_ = singleExtensions;
}

LibOrgBouncycastleAsn1OcspSingleResponse *new_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1OcspOcspCertID *certID, LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *certStatus, LibOrgBouncycastleAsn1ASN1GeneralizedTime *thisUpdate, LibOrgBouncycastleAsn1ASN1GeneralizedTime *nextUpdate, LibOrgBouncycastleAsn1X509Extensions *singleExtensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspSingleResponse, initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509Extensions_, certID, certStatus, thisUpdate, nextUpdate, singleExtensions)
}

LibOrgBouncycastleAsn1OcspSingleResponse *create_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1OcspOcspCertID *certID, LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *certStatus, LibOrgBouncycastleAsn1ASN1GeneralizedTime *thisUpdate, LibOrgBouncycastleAsn1ASN1GeneralizedTime *nextUpdate, LibOrgBouncycastleAsn1X509Extensions *singleExtensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspSingleResponse, initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509Extensions_, certID, certStatus, thisUpdate, nextUpdate, singleExtensions)
}

void LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspSingleResponse *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certID_ = LibOrgBouncycastleAsn1OcspOcspCertID_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->certStatus_ = LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->thisUpdate_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([seq getObjectAtWithInt:2]);
  if ([seq size] > 4) {
    self->nextUpdate_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:3], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true);
    self->singleExtensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:4], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true);
  }
  else if ([seq size] > 3) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:3], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
    if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo] == 0) {
      self->nextUpdate_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
    }
    else {
      self->singleExtensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
    }
  }
}

LibOrgBouncycastleAsn1OcspSingleResponse *new_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspSingleResponse, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspSingleResponse *create_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspSingleResponse, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspSingleResponse *LibOrgBouncycastleAsn1OcspSingleResponse_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1OcspSingleResponse_initialize();
  return LibOrgBouncycastleAsn1OcspSingleResponse_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1OcspSingleResponse *LibOrgBouncycastleAsn1OcspSingleResponse_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1OcspSingleResponse_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1OcspSingleResponse class]]) {
    return (LibOrgBouncycastleAsn1OcspSingleResponse *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1OcspSingleResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1OcspSingleResponse)