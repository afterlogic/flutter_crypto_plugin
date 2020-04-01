//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/CMCStatusInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Asn1CmcUtils.h"
#include "CMCFailInfo.h"
#include "CMCStatus.h"
#include "CMCStatusInfo.h"
#include "DERSequence.h"
#include "DERUTF8String.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "PendInfo.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcCMCStatusInfo () {
 @public
  LibOrgBouncycastleAsn1CmcCMCStatus *cMCStatus_;
  LibOrgBouncycastleAsn1ASN1Sequence *bodyList_;
  LibOrgBouncycastleAsn1DERUTF8String *statusString_;
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *otherInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcCMCStatusInfo, cMCStatus_, LibOrgBouncycastleAsn1CmcCMCStatus *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcCMCStatusInfo, bodyList_, LibOrgBouncycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcCMCStatusInfo, statusString_, LibOrgBouncycastleAsn1DERUTF8String *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcCMCStatusInfo, otherInfo_, LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcCMCStatusInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcCMCStatusInfo *new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcCMCStatusInfo *create_LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@interface LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo () {
 @public
  LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo_;
  LibOrgBouncycastleAsn1CmcPendInfo *pendInfo_;
}

+ (LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *)getInstanceWithId:(id)obj;

- (instancetype)initWithLibOrgBouncycastleAsn1CmcCMCFailInfo:(LibOrgBouncycastleAsn1CmcCMCFailInfo *)failInfo
                       withLibOrgBouncycastleAsn1CmcPendInfo:(LibOrgBouncycastleAsn1CmcPendInfo *)pendInfo;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, failInfo_, LibOrgBouncycastleAsn1CmcCMCFailInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, pendInfo_, LibOrgBouncycastleAsn1CmcPendInfo *)

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_getInstanceWithId_(id obj);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *self, LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo, LibOrgBouncycastleAsn1CmcPendInfo *pendInfo);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo, LibOrgBouncycastleAsn1CmcPendInfo *pendInfo) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *create_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo, LibOrgBouncycastleAsn1CmcPendInfo *pendInfo);

@implementation LibOrgBouncycastleAsn1CmcCMCStatusInfo

- (instancetype)initWithLibOrgBouncycastleAsn1CmcCMCStatus:(LibOrgBouncycastleAsn1CmcCMCStatus *)cMCStatus
                    withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)bodyList
                   withLibOrgBouncycastleAsn1DERUTF8String:(LibOrgBouncycastleAsn1DERUTF8String *)statusString
      withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo:(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *)otherInfo {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1CmcCMCStatus_withLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_(self, cMCStatus, bodyList, statusString, otherInfo);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcCMCStatusInfo *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmcCMCStatusInfo_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:cMCStatus_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:bodyList_];
  if (statusString_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:statusString_];
  }
  if (otherInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:otherInfo_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (LibOrgBouncycastleAsn1CmcCMCStatus *)getCMCStatus {
  return cMCStatus_;
}

- (IOSObjectArray *)getBodyList {
  return LibOrgBouncycastleAsn1CmcAsn1CmcUtils_toBodyPartIDArrayWithLibOrgBouncycastleAsn1ASN1Sequence_(bodyList_);
}

- (LibOrgBouncycastleAsn1DERUTF8String *)getStatusString {
  return statusString_;
}

- (jboolean)hasOtherInfo {
  return otherInfo_ != nil;
}

- (LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *)getOtherInfo {
  return otherInfo_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcCMCStatusInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcCMCStatus;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CmcBodyPartID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERUTF8String;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmcCMCStatus:withLibOrgBouncycastleAsn1ASN1Sequence:withLibOrgBouncycastleAsn1DERUTF8String:withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(toASN1Primitive);
  methods[4].selector = @selector(getCMCStatus);
  methods[5].selector = @selector(getBodyList);
  methods[6].selector = @selector(getStatusString);
  methods[7].selector = @selector(hasOtherInfo);
  methods[8].selector = @selector(getOtherInfo);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cMCStatus_", "LLibOrgBouncycastleAsn1CmcCMCStatus;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "bodyList_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "statusString_", "LLibOrgBouncycastleAsn1DERUTF8String;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "otherInfo_", "LLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmcCMCStatus;LLibOrgBouncycastleAsn1ASN1Sequence;LLibOrgBouncycastleAsn1DERUTF8String;LLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcCMCStatusInfo = { "CMCStatusInfo", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 9, 4, -1, 4, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcCMCStatusInfo;
}

@end

void LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1CmcCMCStatus_withLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_(LibOrgBouncycastleAsn1CmcCMCStatusInfo *self, LibOrgBouncycastleAsn1CmcCMCStatus *cMCStatus, LibOrgBouncycastleAsn1ASN1Sequence *bodyList, LibOrgBouncycastleAsn1DERUTF8String *statusString, LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *otherInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->cMCStatus_ = cMCStatus;
  self->bodyList_ = bodyList;
  self->statusString_ = statusString;
  self->otherInfo_ = otherInfo;
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo *new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1CmcCMCStatus_withLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_(LibOrgBouncycastleAsn1CmcCMCStatus *cMCStatus, LibOrgBouncycastleAsn1ASN1Sequence *bodyList, LibOrgBouncycastleAsn1DERUTF8String *statusString, LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *otherInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo, initWithLibOrgBouncycastleAsn1CmcCMCStatus_withLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_, cMCStatus, bodyList, statusString, otherInfo)
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo *create_LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1CmcCMCStatus_withLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_(LibOrgBouncycastleAsn1CmcCMCStatus *cMCStatus, LibOrgBouncycastleAsn1ASN1Sequence *bodyList, LibOrgBouncycastleAsn1DERUTF8String *statusString, LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *otherInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo, initWithLibOrgBouncycastleAsn1CmcCMCStatus_withLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_, cMCStatus, bodyList, statusString, otherInfo)
}

void LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcCMCStatusInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 2 || [seq size] > 4) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->cMCStatus_ = LibOrgBouncycastleAsn1CmcCMCStatus_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->bodyList_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:1]);
  if ([seq size] > 3) {
    self->statusString_ = LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithId_([seq getObjectAtWithInt:2]);
    self->otherInfo_ = LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_getInstanceWithId_([seq getObjectAtWithInt:3]);
  }
  else if ([seq size] > 2) {
    if ([[seq getObjectAtWithInt:2] isKindOfClass:[LibOrgBouncycastleAsn1DERUTF8String class]]) {
      self->statusString_ = LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithId_([seq getObjectAtWithInt:2]);
      self->otherInfo_ = nil;
    }
    else {
      self->statusString_ = nil;
      self->otherInfo_ = LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_getInstanceWithId_([seq getObjectAtWithInt:2]);
    }
  }
  else {
    self->statusString_ = nil;
    self->otherInfo_ = nil;
  }
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo *new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo *create_LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo *LibOrgBouncycastleAsn1CmcCMCStatusInfo_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmcCMCStatusInfo class]]) {
    return (LibOrgBouncycastleAsn1CmcCMCStatusInfo *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcCMCStatusInfo)

@implementation LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo

+ (LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmcCMCFailInfo:(LibOrgBouncycastleAsn1CmcCMCFailInfo *)failInfo {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_(self, failInfo);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmcPendInfo:(LibOrgBouncycastleAsn1CmcPendInfo *)pendInfo {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcPendInfo_(self, pendInfo);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmcCMCFailInfo:(LibOrgBouncycastleAsn1CmcCMCFailInfo *)failInfo
                       withLibOrgBouncycastleAsn1CmcPendInfo:(LibOrgBouncycastleAsn1CmcPendInfo *)pendInfo {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(self, failInfo, pendInfo);
  return self;
}

- (jboolean)isFailInfo {
  return failInfo_ != nil;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (pendInfo_ != nil) {
    return [pendInfo_ toASN1Primitive];
  }
  return [((LibOrgBouncycastleAsn1CmcCMCFailInfo *) nil_chk(failInfo_)) toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo;", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1CmcCMCFailInfo:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1CmcPendInfo:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CmcCMCFailInfo:withLibOrgBouncycastleAsn1CmcPendInfo:);
  methods[4].selector = @selector(isFailInfo);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "failInfo_", "LLibOrgBouncycastleAsn1CmcCMCFailInfo;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "pendInfo_", "LLibOrgBouncycastleAsn1CmcPendInfo;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1CmcCMCFailInfo;", "LLibOrgBouncycastleAsn1CmcPendInfo;", "LLibOrgBouncycastleAsn1CmcCMCFailInfo;LLibOrgBouncycastleAsn1CmcPendInfo;", "LLibOrgBouncycastleAsn1CmcCMCStatusInfo;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo = { "OtherInfo", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x9, 6, 2, 5, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo;
}

@end

LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo class]]) {
    return (LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *) obj;
  }
  if ([LibOrgBouncycastleAsn1ASN1Encodable_class_() isInstance:obj]) {
    id<LibOrgBouncycastleAsn1ASN1Encodable> asn1Value = [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check(obj, LibOrgBouncycastleAsn1ASN1Encodable_class_())))) toASN1Primitive];
    if ([asn1Value isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
      return new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_(LibOrgBouncycastleAsn1CmcCMCFailInfo_getInstanceWithId_(asn1Value));
    }
    else if ([asn1Value isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
      return new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcPendInfo_getInstanceWithId_(asn1Value));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in getInstance(): ", [[nil_chk(obj) java_getClass] getName]));
}

void LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *self, LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo) {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(self, failInfo, nil);
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_(LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_, failInfo)
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *create_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_(LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_, failInfo)
}

void LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *self, LibOrgBouncycastleAsn1CmcPendInfo *pendInfo) {
  LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(self, nil, pendInfo);
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcPendInfo *pendInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, initWithLibOrgBouncycastleAsn1CmcPendInfo_, pendInfo)
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *create_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcPendInfo *pendInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, initWithLibOrgBouncycastleAsn1CmcPendInfo_, pendInfo)
}

void LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *self, LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo, LibOrgBouncycastleAsn1CmcPendInfo *pendInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->failInfo_ = failInfo;
  self->pendInfo_ = pendInfo;
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *new_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo, LibOrgBouncycastleAsn1CmcPendInfo *pendInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_, failInfo, pendInfo)
}

LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo *create_LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo_initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_(LibOrgBouncycastleAsn1CmcCMCFailInfo *failInfo, LibOrgBouncycastleAsn1CmcPendInfo *pendInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo, initWithLibOrgBouncycastleAsn1CmcCMCFailInfo_withLibOrgBouncycastleAsn1CmcPendInfo_, failInfo, pendInfo)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcCMCStatusInfo_OtherInfo)