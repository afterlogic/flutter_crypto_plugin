//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PKIStatusInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "PKIFailureInfo.h"
#include "PKIFreeText.h"
#include "PKIStatus.h"
#include "PKIStatusInfo.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1CmpPKIStatusInfo ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpPKIStatusInfo

+ (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmpPKIStatus:(LibOrgBouncycastleAsn1CmpPKIStatus *)status {
  LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_(self, status);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmpPKIStatus:(LibOrgBouncycastleAsn1CmpPKIStatus *)status
                  withLibOrgBouncycastleAsn1CmpPKIFreeText:(LibOrgBouncycastleAsn1CmpPKIFreeText *)statusString {
  LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_(self, status, statusString);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmpPKIStatus:(LibOrgBouncycastleAsn1CmpPKIStatus *)status
                  withLibOrgBouncycastleAsn1CmpPKIFreeText:(LibOrgBouncycastleAsn1CmpPKIFreeText *)statusString
               withLibOrgBouncycastleAsn1CmpPKIFailureInfo:(LibOrgBouncycastleAsn1CmpPKIFailureInfo *)failInfo {
  LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_(self, status, statusString, failInfo);
  return self;
}

- (JavaMathBigInteger *)getStatus {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(status_)) getValue];
}

- (LibOrgBouncycastleAsn1CmpPKIFreeText *)getStatusString {
  return statusString_;
}

- (LibOrgBouncycastleAsn1DERBitString *)getFailInfo {
  return failInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:status_];
  if (statusString_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:statusString_];
  }
  if (failInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:failInfo_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIFreeText;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CmpPKIStatus:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1CmpPKIStatus:withLibOrgBouncycastleAsn1CmpPKIFreeText:);
  methods[5].selector = @selector(initWithLibOrgBouncycastleAsn1CmpPKIStatus:withLibOrgBouncycastleAsn1CmpPKIFreeText:withLibOrgBouncycastleAsn1CmpPKIFailureInfo:);
  methods[6].selector = @selector(getStatus);
  methods[7].selector = @selector(getStatusString);
  methods[8].selector = @selector(getFailInfo);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "status_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "statusString_", "LLibOrgBouncycastleAsn1CmpPKIFreeText;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "failInfo_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1CmpPKIStatus;", "LLibOrgBouncycastleAsn1CmpPKIStatus;LLibOrgBouncycastleAsn1CmpPKIFreeText;", "LLibOrgBouncycastleAsn1CmpPKIStatus;LLibOrgBouncycastleAsn1CmpPKIFreeText;LLibOrgBouncycastleAsn1CmpPKIFailureInfo;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpPKIStatusInfo = { "PKIStatusInfo", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpPKIStatusInfo;
}

@end

LibOrgBouncycastleAsn1CmpPKIStatusInfo *LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmpPKIStatusInfo_initialize();
  return LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmpPKIStatusInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmpPKIStatusInfo class]]) {
    return (LibOrgBouncycastleAsn1CmpPKIStatusInfo *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->status_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->statusString_ = nil;
  self->failInfo_ = nil;
  if ([seq size] > 2) {
    self->statusString_ = LibOrgBouncycastleAsn1CmpPKIFreeText_getInstanceWithId_([seq getObjectAtWithInt:1]);
    self->failInfo_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_([seq getObjectAtWithInt:2]);
  }
  else if ([seq size] > 1) {
    id obj = [seq getObjectAtWithInt:1];
    if ([obj isKindOfClass:[LibOrgBouncycastleAsn1DERBitString class]]) {
      self->failInfo_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_(obj);
    }
    else {
      self->statusString_ = LibOrgBouncycastleAsn1CmpPKIFreeText_getInstanceWithId_(obj);
    }
  }
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1CmpPKIStatus *status) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->status_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1CmpPKIStatus *) nil_chk(status)) toASN1Primitive]);
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_(LibOrgBouncycastleAsn1CmpPKIStatus *status) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1CmpPKIStatus_, status)
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_(LibOrgBouncycastleAsn1CmpPKIStatus *status) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1CmpPKIStatus_, status)
}

void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->status_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1CmpPKIStatus *) nil_chk(status)) toASN1Primitive]);
  self->statusString_ = statusString;
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_, status, statusString)
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_, status, statusString)
}

void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString, LibOrgBouncycastleAsn1CmpPKIFailureInfo *failInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->status_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1CmpPKIStatus *) nil_chk(status)) toASN1Primitive]);
  self->statusString_ = statusString;
  self->failInfo_ = failInfo;
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString, LibOrgBouncycastleAsn1CmpPKIFailureInfo *failInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_, status, statusString, failInfo)
}

LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString, LibOrgBouncycastleAsn1CmpPKIFailureInfo *failInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIStatusInfo, initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_, status, statusString, failInfo)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpPKIStatusInfo)
