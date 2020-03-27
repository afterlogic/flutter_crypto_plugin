//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/RecipientInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "KEKRecipientInfo.h"
#include "KeyAgreeRecipientInfo.h"
#include "KeyTransRecipientInfo.h"
#include "OtherRecipientInfo.h"
#include "PasswordRecipientInfo.h"
#include "RecipientInfo.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleAsn1CmsRecipientInfo ()

- (LibOrgBouncycastleAsn1CmsKEKRecipientInfo *)getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)o;

@end

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsKEKRecipientInfo *LibOrgBouncycastleAsn1CmsRecipientInfo_getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1ASN1TaggedObject *o);

@implementation LibOrgBouncycastleAsn1CmsRecipientInfo

- (instancetype)initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo:(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *)info {
  LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_(self, info);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo:(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *)info {
  LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_(self, info);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo:(LibOrgBouncycastleAsn1CmsKEKRecipientInfo *)info {
  LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo_(self, info);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo:(LibOrgBouncycastleAsn1CmsPasswordRecipientInfo *)info {
  LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo_(self, info);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo:(LibOrgBouncycastleAsn1CmsOtherRecipientInfo *)info {
  LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo_(self, info);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)info {
  LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Primitive_(self, info);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsRecipientInfo *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmsRecipientInfo_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  if ([info_ isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = (LibOrgBouncycastleAsn1ASN1TaggedObject *) info_;
    switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo]) {
      case 1:
      return [((LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *) nil_chk(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) getVersion];
      case 2:
      return [((LibOrgBouncycastleAsn1CmsKEKRecipientInfo *) nil_chk(LibOrgBouncycastleAsn1CmsRecipientInfo_getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject_(self, o))) getVersion];
      case 3:
      return [((LibOrgBouncycastleAsn1CmsPasswordRecipientInfo *) nil_chk(LibOrgBouncycastleAsn1CmsPasswordRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) getVersion];
      case 4:
      return new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(0);
      default:
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"unknown tag");
    }
  }
  return [((LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *) nil_chk(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_getInstanceWithId_(info_))) getVersion];
}

- (jboolean)isTagged {
  return ([info_ isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]);
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getInfo {
  if ([info_ isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = (LibOrgBouncycastleAsn1ASN1TaggedObject *) info_;
    switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo]) {
      case 1:
      return LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
      case 2:
      return LibOrgBouncycastleAsn1CmsRecipientInfo_getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject_(self, o);
      case 3:
      return LibOrgBouncycastleAsn1CmsPasswordRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
      case 4:
      return LibOrgBouncycastleAsn1CmsOtherRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
      default:
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"unknown tag");
    }
  }
  return LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_getInstanceWithId_(info_);
}

- (LibOrgBouncycastleAsn1CmsKEKRecipientInfo *)getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)o {
  return LibOrgBouncycastleAsn1CmsRecipientInfo_getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject_(self, o);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(info_)) toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsRecipientInfo;", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsKEKRecipientInfo;", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo:);
  methods[5].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[6].selector = @selector(getInstanceWithId:);
  methods[7].selector = @selector(getVersion);
  methods[8].selector = @selector(isTagged);
  methods[9].selector = @selector(getInfo);
  methods[10].selector = @selector(getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject:);
  methods[11].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "info_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo;", "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo;", "LLibOrgBouncycastleAsn1CmsKEKRecipientInfo;", "LLibOrgBouncycastleAsn1CmsPasswordRecipientInfo;", "LLibOrgBouncycastleAsn1CmsOtherRecipientInfo;", "LLibOrgBouncycastleAsn1ASN1Primitive;", "getInstance", "LNSObject;", "getKEKInfo", "LLibOrgBouncycastleAsn1ASN1TaggedObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsRecipientInfo = { "RecipientInfo", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 12, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsRecipientInfo;
}

@end

void LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *info) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->info_ = info;
}

LibOrgBouncycastleAsn1CmsRecipientInfo *new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_, info)
}

LibOrgBouncycastleAsn1CmsRecipientInfo *create_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_, info)
}

void LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *info) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->info_ = new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, info);
}

LibOrgBouncycastleAsn1CmsRecipientInfo *new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_, info)
}

LibOrgBouncycastleAsn1CmsRecipientInfo *create_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientInfo_, info)
}

void LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1CmsKEKRecipientInfo *info) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->info_ = new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 2, info);
}

LibOrgBouncycastleAsn1CmsRecipientInfo *new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo_(LibOrgBouncycastleAsn1CmsKEKRecipientInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo_, info)
}

LibOrgBouncycastleAsn1CmsRecipientInfo *create_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo_(LibOrgBouncycastleAsn1CmsKEKRecipientInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsKEKRecipientInfo_, info)
}

void LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1CmsPasswordRecipientInfo *info) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->info_ = new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 3, info);
}

LibOrgBouncycastleAsn1CmsRecipientInfo *new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo_(LibOrgBouncycastleAsn1CmsPasswordRecipientInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo_, info)
}

LibOrgBouncycastleAsn1CmsRecipientInfo *create_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo_(LibOrgBouncycastleAsn1CmsPasswordRecipientInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsPasswordRecipientInfo_, info)
}

void LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1CmsOtherRecipientInfo *info) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->info_ = new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 4, info);
}

LibOrgBouncycastleAsn1CmsRecipientInfo *new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo_(LibOrgBouncycastleAsn1CmsOtherRecipientInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo_, info)
}

LibOrgBouncycastleAsn1CmsRecipientInfo *create_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo_(LibOrgBouncycastleAsn1CmsOtherRecipientInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1CmsOtherRecipientInfo_, info)
}

void LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1ASN1Primitive *info) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->info_ = info;
}

LibOrgBouncycastleAsn1CmsRecipientInfo *new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1ASN1Primitive_, info)
}

LibOrgBouncycastleAsn1CmsRecipientInfo *create_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientInfo, initWithLibOrgBouncycastleAsn1ASN1Primitive_, info)
}

LibOrgBouncycastleAsn1CmsRecipientInfo *LibOrgBouncycastleAsn1CmsRecipientInfo_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmsRecipientInfo_initialize();
  if (o == nil || [o isKindOfClass:[LibOrgBouncycastleAsn1CmsRecipientInfo class]]) {
    return (LibOrgBouncycastleAsn1CmsRecipientInfo *) cast_chk(o, [LibOrgBouncycastleAsn1CmsRecipientInfo class]);
  }
  else if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Primitive_((LibOrgBouncycastleAsn1ASN1Sequence *) o);
  }
  else if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    return new_LibOrgBouncycastleAsn1CmsRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Primitive_((LibOrgBouncycastleAsn1ASN1TaggedObject *) o);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in factory: ", [[o java_getClass] getName]));
}

LibOrgBouncycastleAsn1CmsKEKRecipientInfo *LibOrgBouncycastleAsn1CmsRecipientInfo_getKEKInfoWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1CmsRecipientInfo *self, LibOrgBouncycastleAsn1ASN1TaggedObject *o) {
  if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) isExplicit]) {
    return LibOrgBouncycastleAsn1CmsKEKRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
  }
  else {
    return LibOrgBouncycastleAsn1CmsKEKRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsRecipientInfo)
