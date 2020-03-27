//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/Request.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "Extensions.h"
#include "J2ObjC_source.h"
#include "OcspCertID.h"
#include "Request.h"

@interface LibOrgBouncycastleAsn1OcspRequest ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspRequest *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspRequest *new_LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspRequest *create_LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1OcspRequest

- (instancetype)initWithLibOrgBouncycastleAsn1OcspOcspCertID:(LibOrgBouncycastleAsn1OcspOcspCertID *)reqCert
                    withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)singleRequestExtensions {
  LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1X509Extensions_(self, reqCert, singleRequestExtensions);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1OcspRequest *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                 withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1OcspRequest_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1OcspRequest *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1OcspRequest_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1OcspOcspCertID *)getReqCert {
  return reqCert_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getSingleRequestExtensions {
  return singleRequestExtensions_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:reqCert_];
  if (singleRequestExtensions_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, singleRequestExtensions_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspRequest;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspRequest;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspOcspCertID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1OcspOcspCertID:withLibOrgBouncycastleAsn1X509Extensions:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getReqCert);
  methods[5].selector = @selector(getSingleRequestExtensions);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "reqCert_", "LLibOrgBouncycastleAsn1OcspOcspCertID;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "singleRequestExtensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1OcspOcspCertID;LLibOrgBouncycastleAsn1X509Extensions;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1OcspRequest = { "Request", "lib.org.bouncycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1OcspRequest;
}

@end

void LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1OcspRequest *self, LibOrgBouncycastleAsn1OcspOcspCertID *reqCert, LibOrgBouncycastleAsn1X509Extensions *singleRequestExtensions) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->reqCert_ = reqCert;
  self->singleRequestExtensions_ = singleRequestExtensions;
}

LibOrgBouncycastleAsn1OcspRequest *new_LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1OcspOcspCertID *reqCert, LibOrgBouncycastleAsn1X509Extensions *singleRequestExtensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspRequest, initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1X509Extensions_, reqCert, singleRequestExtensions)
}

LibOrgBouncycastleAsn1OcspRequest *create_LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1OcspOcspCertID *reqCert, LibOrgBouncycastleAsn1X509Extensions *singleRequestExtensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspRequest, initWithLibOrgBouncycastleAsn1OcspOcspCertID_withLibOrgBouncycastleAsn1X509Extensions_, reqCert, singleRequestExtensions)
}

void LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspRequest *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->reqCert_ = LibOrgBouncycastleAsn1OcspOcspCertID_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  if ([seq size] == 2) {
    self->singleRequestExtensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true);
  }
}

LibOrgBouncycastleAsn1OcspRequest *new_LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspRequest, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspRequest *create_LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspRequest, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspRequest *LibOrgBouncycastleAsn1OcspRequest_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1OcspRequest_initialize();
  return LibOrgBouncycastleAsn1OcspRequest_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1OcspRequest *LibOrgBouncycastleAsn1OcspRequest_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1OcspRequest_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1OcspRequest class]]) {
    return (LibOrgBouncycastleAsn1OcspRequest *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1OcspRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1OcspRequest)
