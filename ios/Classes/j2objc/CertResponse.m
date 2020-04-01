//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/CertResponse.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "CertResponse.h"
#include "CertifiedKeyPair.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "PKIStatusInfo.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmpCertResponse () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *certReqId_;
  LibOrgBouncycastleAsn1CmpPKIStatusInfo *status_;
  LibOrgBouncycastleAsn1CmpCertifiedKeyPair *certifiedKeyPair_;
  LibOrgBouncycastleAsn1ASN1OctetString *rspInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpCertResponse, certReqId_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpCertResponse, status_, LibOrgBouncycastleAsn1CmpPKIStatusInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpCertResponse, certifiedKeyPair_, LibOrgBouncycastleAsn1CmpCertifiedKeyPair *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpCertResponse, rspInfo_, LibOrgBouncycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpCertResponse *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpCertResponse *new_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpCertResponse *create_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpCertResponse

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpCertResponse *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpCertResponse_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)certReqId
               withLibOrgBouncycastleAsn1CmpPKIStatusInfo:(LibOrgBouncycastleAsn1CmpPKIStatusInfo *)status {
  LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(self, certReqId, status);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)certReqId
               withLibOrgBouncycastleAsn1CmpPKIStatusInfo:(LibOrgBouncycastleAsn1CmpPKIStatusInfo *)status
            withLibOrgBouncycastleAsn1CmpCertifiedKeyPair:(LibOrgBouncycastleAsn1CmpCertifiedKeyPair *)certifiedKeyPair
                withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)rspInfo {
  LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1CmpCertifiedKeyPair_withLibOrgBouncycastleAsn1ASN1OctetString_(self, certReqId, status, certifiedKeyPair, rspInfo);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getCertReqId {
  return certReqId_;
}

- (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getStatus {
  return status_;
}

- (LibOrgBouncycastleAsn1CmpCertifiedKeyPair *)getCertifiedKeyPair {
  return certifiedKeyPair_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certReqId_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:status_];
  if (certifiedKeyPair_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certifiedKeyPair_];
  }
  if (rspInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:rspInfo_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpCertResponse;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpCertifiedKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1CmpPKIStatusInfo:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1CmpPKIStatusInfo:withLibOrgBouncycastleAsn1CmpCertifiedKeyPair:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[4].selector = @selector(getCertReqId);
  methods[5].selector = @selector(getStatus);
  methods[6].selector = @selector(getCertifiedKeyPair);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certReqId_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "status_", "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certifiedKeyPair_", "LLibOrgBouncycastleAsn1CmpCertifiedKeyPair;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "rspInfo_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1CmpPKIStatusInfo;LLibOrgBouncycastleAsn1CmpCertifiedKeyPair;LLibOrgBouncycastleAsn1ASN1OctetString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpCertResponse = { "CertResponse", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 8, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpCertResponse;
}

@end

void LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpCertResponse *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certReqId_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->status_ = LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithId_([seq getObjectAtWithInt:1]);
  if ([seq size] >= 3) {
    if ([seq size] == 3) {
      id<LibOrgBouncycastleAsn1ASN1Encodable> o = [seq getObjectAtWithInt:2];
      if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1OctetString class]]) {
        self->rspInfo_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_(o);
      }
      else {
        self->certifiedKeyPair_ = LibOrgBouncycastleAsn1CmpCertifiedKeyPair_getInstanceWithId_(o);
      }
    }
    else {
      self->certifiedKeyPair_ = LibOrgBouncycastleAsn1CmpCertifiedKeyPair_getInstanceWithId_([seq getObjectAtWithInt:2]);
      self->rspInfo_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:3]);
    }
  }
}

LibOrgBouncycastleAsn1CmpCertResponse *new_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpCertResponse, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpCertResponse *create_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpCertResponse, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpCertResponse *LibOrgBouncycastleAsn1CmpCertResponse_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpCertResponse_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpCertResponse class]]) {
    return (LibOrgBouncycastleAsn1CmpCertResponse *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1CmpCertResponse *self, LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status) {
  LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1CmpCertifiedKeyPair_withLibOrgBouncycastleAsn1ASN1OctetString_(self, certReqId, status, nil, nil);
}

LibOrgBouncycastleAsn1CmpCertResponse *new_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpCertResponse, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_, certReqId, status)
}

LibOrgBouncycastleAsn1CmpCertResponse *create_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpCertResponse, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_, certReqId, status)
}

void LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1CmpCertifiedKeyPair_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmpCertResponse *self, LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status, LibOrgBouncycastleAsn1CmpCertifiedKeyPair *certifiedKeyPair, LibOrgBouncycastleAsn1ASN1OctetString *rspInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (certReqId == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'certReqId' cannot be null");
  }
  if (status == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'status' cannot be null");
  }
  self->certReqId_ = certReqId;
  self->status_ = status;
  self->certifiedKeyPair_ = certifiedKeyPair;
  self->rspInfo_ = rspInfo;
}

LibOrgBouncycastleAsn1CmpCertResponse *new_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1CmpCertifiedKeyPair_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status, LibOrgBouncycastleAsn1CmpCertifiedKeyPair *certifiedKeyPair, LibOrgBouncycastleAsn1ASN1OctetString *rspInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpCertResponse, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1CmpCertifiedKeyPair_withLibOrgBouncycastleAsn1ASN1OctetString_, certReqId, status, certifiedKeyPair, rspInfo)
}

LibOrgBouncycastleAsn1CmpCertResponse *create_LibOrgBouncycastleAsn1CmpCertResponse_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1CmpCertifiedKeyPair_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status, LibOrgBouncycastleAsn1CmpCertifiedKeyPair *certifiedKeyPair, LibOrgBouncycastleAsn1ASN1OctetString *rspInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpCertResponse, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1CmpCertifiedKeyPair_withLibOrgBouncycastleAsn1ASN1OctetString_, certReqId, status, certifiedKeyPair, rspInfo)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpCertResponse)