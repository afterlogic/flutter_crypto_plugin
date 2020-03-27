//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/RevAnnContent.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "CertId.h"
#include "DERSequence.h"
#include "Extensions.h"
#include "J2ObjC_source.h"
#include "PKIStatus.h"
#include "RevAnnContent.h"

@interface LibOrgBouncycastleAsn1CmpRevAnnContent () {
 @public
  LibOrgBouncycastleAsn1CmpPKIStatus *status_;
  LibOrgBouncycastleAsn1CrmfCertId *certId_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *willBeRevokedAt_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *badSinceDate_;
  LibOrgBouncycastleAsn1X509Extensions *crlDetails_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpRevAnnContent, status_, LibOrgBouncycastleAsn1CmpPKIStatus *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpRevAnnContent, certId_, LibOrgBouncycastleAsn1CrmfCertId *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpRevAnnContent, willBeRevokedAt_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpRevAnnContent, badSinceDate_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpRevAnnContent, crlDetails_, LibOrgBouncycastleAsn1X509Extensions *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpRevAnnContent *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpRevAnnContent *new_LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpRevAnnContent *create_LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpRevAnnContent

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpRevAnnContent *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpRevAnnContent_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1CmpPKIStatus *)getStatus {
  return status_;
}

- (LibOrgBouncycastleAsn1CrmfCertId *)getCertId {
  return certId_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getWillBeRevokedAt {
  return willBeRevokedAt_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getBadSinceDate {
  return badSinceDate_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getCrlDetails {
  return crlDetails_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:status_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certId_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:willBeRevokedAt_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:badSinceDate_];
  if (crlDetails_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:crlDetails_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpRevAnnContent;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIStatus;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfCertId;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(getStatus);
  methods[3].selector = @selector(getCertId);
  methods[4].selector = @selector(getWillBeRevokedAt);
  methods[5].selector = @selector(getBadSinceDate);
  methods[6].selector = @selector(getCrlDetails);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "status_", "LLibOrgBouncycastleAsn1CmpPKIStatus;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certId_", "LLibOrgBouncycastleAsn1CrmfCertId;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "willBeRevokedAt_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "badSinceDate_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "crlDetails_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpRevAnnContent = { "RevAnnContent", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 8, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpRevAnnContent;
}

@end

void LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpRevAnnContent *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->status_ = LibOrgBouncycastleAsn1CmpPKIStatus_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->certId_ = LibOrgBouncycastleAsn1CrmfCertId_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->willBeRevokedAt_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([seq getObjectAtWithInt:2]);
  self->badSinceDate_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([seq getObjectAtWithInt:3]);
  if ([seq size] > 4) {
    self->crlDetails_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_([seq getObjectAtWithInt:4]);
  }
}

LibOrgBouncycastleAsn1CmpRevAnnContent *new_LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpRevAnnContent, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpRevAnnContent *create_LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpRevAnnContent, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpRevAnnContent *LibOrgBouncycastleAsn1CmpRevAnnContent_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpRevAnnContent_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpRevAnnContent class]]) {
    return (LibOrgBouncycastleAsn1CmpRevAnnContent *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpRevAnnContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpRevAnnContent)
