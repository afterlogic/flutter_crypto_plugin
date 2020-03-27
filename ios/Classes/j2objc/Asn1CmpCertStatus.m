//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/Asn1CmpCertStatus.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Asn1CmpCertStatus.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PKIStatusInfo.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus () {
 @public
  LibOrgBouncycastleAsn1ASN1OctetString *certHash_;
  LibOrgBouncycastleAsn1ASN1Integer *certReqId_;
  LibOrgBouncycastleAsn1CmpPKIStatusInfo *statusInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, certHash_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, certReqId_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, statusInfo_, LibOrgBouncycastleAsn1CmpPKIStatusInfo *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *new_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *create_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)certHash
           withJavaMathBigInteger:(JavaMathBigInteger *)certReqId {
  LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_(self, certHash, certReqId);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)certHash
           withJavaMathBigInteger:(JavaMathBigInteger *)certReqId
withLibOrgBouncycastleAsn1CmpPKIStatusInfo:(LibOrgBouncycastleAsn1CmpPKIStatusInfo *)statusInfo {
  LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(self, certHash, certReqId, statusInfo);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getCertHash {
  return certHash_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getCertReqId {
  return certReqId_;
}

- (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getStatusInfo {
  return statusInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certHash_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certReqId_];
  if (statusInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:statusInfo_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpAsn1CmpCertStatus;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithByteArray:withJavaMathBigInteger:);
  methods[2].selector = @selector(initWithByteArray:withJavaMathBigInteger:withLibOrgBouncycastleAsn1CmpPKIStatusInfo:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getCertHash);
  methods[5].selector = @selector(getCertReqId);
  methods[6].selector = @selector(getStatusInfo);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certHash_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certReqId_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "statusInfo_", "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "[BLJavaMathBigInteger;", "[BLJavaMathBigInteger;LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus = { "Asn1CmpCertStatus", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus;
}

@end

void LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certHash_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->certReqId_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:1]);
  if ([seq size] > 2) {
    self->statusInfo_ = LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithId_([seq getObjectAtWithInt:2]);
  }
}

LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *new_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *create_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *self, IOSByteArray *certHash, JavaMathBigInteger *certReqId) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certHash_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(certHash);
  self->certReqId_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(certReqId);
}

LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *new_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_(IOSByteArray *certHash, JavaMathBigInteger *certReqId) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, initWithByteArray_withJavaMathBigInteger_, certHash, certReqId)
}

LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *create_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_(IOSByteArray *certHash, JavaMathBigInteger *certReqId) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, initWithByteArray_withJavaMathBigInteger_, certHash, certReqId)
}

void LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *self, IOSByteArray *certHash, JavaMathBigInteger *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *statusInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certHash_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(certHash);
  self->certReqId_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(certReqId);
  self->statusInfo_ = statusInfo;
}

LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *new_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(IOSByteArray *certHash, JavaMathBigInteger *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *statusInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, initWithByteArray_withJavaMathBigInteger_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_, certHash, certReqId, statusInfo)
}

LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *create_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_(IOSByteArray *certHash, JavaMathBigInteger *certReqId, LibOrgBouncycastleAsn1CmpPKIStatusInfo *statusInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus, initWithByteArray_withJavaMathBigInteger_withLibOrgBouncycastleAsn1CmpPKIStatusInfo_, certHash, certReqId, statusInfo)
}

LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus class]]) {
    return (LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpAsn1CmpCertStatus)
