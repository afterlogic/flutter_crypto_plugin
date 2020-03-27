//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/OtherInfo.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"
#include "KeySpecificInfo.h"
#include "OtherInfo.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1X9OtherInfo () {
 @public
  LibOrgBouncycastleAsn1X9KeySpecificInfo *keyInfo_;
  LibOrgBouncycastleAsn1ASN1OctetString *partyAInfo_;
  LibOrgBouncycastleAsn1ASN1OctetString *suppPubInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9OtherInfo, keyInfo_, LibOrgBouncycastleAsn1X9KeySpecificInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9OtherInfo, partyAInfo_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9OtherInfo, suppPubInfo_, LibOrgBouncycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9OtherInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X9OtherInfo *new_LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X9OtherInfo *create_LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X9OtherInfo

- (instancetype)initWithLibOrgBouncycastleAsn1X9KeySpecificInfo:(LibOrgBouncycastleAsn1X9KeySpecificInfo *)keyInfo
                      withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)partyAInfo
                      withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)suppPubInfo {
  LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1X9KeySpecificInfo_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_(self, keyInfo, partyAInfo, suppPubInfo);
  return self;
}

+ (LibOrgBouncycastleAsn1X9OtherInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X9OtherInfo_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (LibOrgBouncycastleAsn1X9KeySpecificInfo *)getKeyInfo {
  return keyInfo_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getPartyAInfo {
  return partyAInfo_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getSuppPubInfo {
  return suppPubInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:keyInfo_];
  if (partyAInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(0, partyAInfo_)];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(2, suppPubInfo_)];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9OtherInfo;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9KeySpecificInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X9KeySpecificInfo:withLibOrgBouncycastleAsn1ASN1OctetString:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getKeyInfo);
  methods[4].selector = @selector(getPartyAInfo);
  methods[5].selector = @selector(getSuppPubInfo);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keyInfo_", "LLibOrgBouncycastleAsn1X9KeySpecificInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "partyAInfo_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "suppPubInfo_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X9KeySpecificInfo;LLibOrgBouncycastleAsn1ASN1OctetString;LLibOrgBouncycastleAsn1ASN1OctetString;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X9OtherInfo = { "OtherInfo", "lib.org.bouncycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X9OtherInfo;
}

@end

void LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1X9KeySpecificInfo_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X9OtherInfo *self, LibOrgBouncycastleAsn1X9KeySpecificInfo *keyInfo, LibOrgBouncycastleAsn1ASN1OctetString *partyAInfo, LibOrgBouncycastleAsn1ASN1OctetString *suppPubInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->keyInfo_ = keyInfo;
  self->partyAInfo_ = partyAInfo;
  self->suppPubInfo_ = suppPubInfo;
}

LibOrgBouncycastleAsn1X9OtherInfo *new_LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1X9KeySpecificInfo_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X9KeySpecificInfo *keyInfo, LibOrgBouncycastleAsn1ASN1OctetString *partyAInfo, LibOrgBouncycastleAsn1ASN1OctetString *suppPubInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9OtherInfo, initWithLibOrgBouncycastleAsn1X9KeySpecificInfo_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_, keyInfo, partyAInfo, suppPubInfo)
}

LibOrgBouncycastleAsn1X9OtherInfo *create_LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1X9KeySpecificInfo_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X9KeySpecificInfo *keyInfo, LibOrgBouncycastleAsn1ASN1OctetString *partyAInfo, LibOrgBouncycastleAsn1ASN1OctetString *suppPubInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9OtherInfo, initWithLibOrgBouncycastleAsn1X9KeySpecificInfo_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_, keyInfo, partyAInfo, suppPubInfo)
}

LibOrgBouncycastleAsn1X9OtherInfo *LibOrgBouncycastleAsn1X9OtherInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X9OtherInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X9OtherInfo class]]) {
    return (LibOrgBouncycastleAsn1X9OtherInfo *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9OtherInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->keyInfo_ = LibOrgBouncycastleAsn1X9KeySpecificInfo_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  while ([e hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
    if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo] == 0) {
      self->partyAInfo_ = (LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk([o getObject], [LibOrgBouncycastleAsn1ASN1OctetString class]);
    }
    else if ([o getTagNo] == 2) {
      self->suppPubInfo_ = (LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk([o getObject], [LibOrgBouncycastleAsn1ASN1OctetString class]);
    }
  }
}

LibOrgBouncycastleAsn1X9OtherInfo *new_LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9OtherInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X9OtherInfo *create_LibOrgBouncycastleAsn1X9OtherInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9OtherInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X9OtherInfo)
