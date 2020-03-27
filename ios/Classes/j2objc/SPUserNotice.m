//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/SPUserNotice.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1String.h"
#include "DERSequence.h"
#include "DisplayText.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "NoticeReference.h"
#include "SPUserNotice.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1EsfSPUserNotice () {
 @public
  LibOrgBouncycastleAsn1X509NoticeReference *noticeRef_;
  LibOrgBouncycastleAsn1X509DisplayText *explicitText_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSPUserNotice, noticeRef_, LibOrgBouncycastleAsn1X509NoticeReference *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSPUserNotice, explicitText_, LibOrgBouncycastleAsn1X509DisplayText *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSPUserNotice *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSPUserNotice *new_LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSPUserNotice *create_LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EsfSPUserNotice

+ (LibOrgBouncycastleAsn1EsfSPUserNotice *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfSPUserNotice_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509NoticeReference:(LibOrgBouncycastleAsn1X509NoticeReference *)noticeRef
                        withLibOrgBouncycastleAsn1X509DisplayText:(LibOrgBouncycastleAsn1X509DisplayText *)explicitText {
  LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1X509NoticeReference_withLibOrgBouncycastleAsn1X509DisplayText_(self, noticeRef, explicitText);
  return self;
}

- (LibOrgBouncycastleAsn1X509NoticeReference *)getNoticeRef {
  return noticeRef_;
}

- (LibOrgBouncycastleAsn1X509DisplayText *)getExplicitText {
  return explicitText_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (noticeRef_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:noticeRef_];
  }
  if (explicitText_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:explicitText_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EsfSPUserNotice;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509NoticeReference;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509DisplayText;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509NoticeReference:withLibOrgBouncycastleAsn1X509DisplayText:);
  methods[3].selector = @selector(getNoticeRef);
  methods[4].selector = @selector(getExplicitText);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "noticeRef_", "LLibOrgBouncycastleAsn1X509NoticeReference;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "explicitText_", "LLibOrgBouncycastleAsn1X509DisplayText;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X509NoticeReference;LLibOrgBouncycastleAsn1X509DisplayText;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfSPUserNotice = { "SPUserNotice", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfSPUserNotice;
}

@end

LibOrgBouncycastleAsn1EsfSPUserNotice *LibOrgBouncycastleAsn1EsfSPUserNotice_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfSPUserNotice_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EsfSPUserNotice class]]) {
    return (LibOrgBouncycastleAsn1EsfSPUserNotice *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSPUserNotice *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    id<LibOrgBouncycastleAsn1ASN1Encodable> object = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([e nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
    if ([object isKindOfClass:[LibOrgBouncycastleAsn1X509DisplayText class]] || [LibOrgBouncycastleAsn1ASN1String_class_() isInstance:object]) {
      self->explicitText_ = LibOrgBouncycastleAsn1X509DisplayText_getInstanceWithId_(object);
    }
    else if ([object isKindOfClass:[LibOrgBouncycastleAsn1X509NoticeReference class]] || [object isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
      self->noticeRef_ = LibOrgBouncycastleAsn1X509NoticeReference_getInstanceWithId_(object);
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid element in 'SPUserNotice': ", [[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(object)) java_getClass] getName]));
    }
  }
}

LibOrgBouncycastleAsn1EsfSPUserNotice *new_LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSPUserNotice, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfSPUserNotice *create_LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSPUserNotice, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1X509NoticeReference_withLibOrgBouncycastleAsn1X509DisplayText_(LibOrgBouncycastleAsn1EsfSPUserNotice *self, LibOrgBouncycastleAsn1X509NoticeReference *noticeRef, LibOrgBouncycastleAsn1X509DisplayText *explicitText) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->noticeRef_ = noticeRef;
  self->explicitText_ = explicitText;
}

LibOrgBouncycastleAsn1EsfSPUserNotice *new_LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1X509NoticeReference_withLibOrgBouncycastleAsn1X509DisplayText_(LibOrgBouncycastleAsn1X509NoticeReference *noticeRef, LibOrgBouncycastleAsn1X509DisplayText *explicitText) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSPUserNotice, initWithLibOrgBouncycastleAsn1X509NoticeReference_withLibOrgBouncycastleAsn1X509DisplayText_, noticeRef, explicitText)
}

LibOrgBouncycastleAsn1EsfSPUserNotice *create_LibOrgBouncycastleAsn1EsfSPUserNotice_initWithLibOrgBouncycastleAsn1X509NoticeReference_withLibOrgBouncycastleAsn1X509DisplayText_(LibOrgBouncycastleAsn1X509NoticeReference *noticeRef, LibOrgBouncycastleAsn1X509DisplayText *explicitText) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSPUserNotice, initWithLibOrgBouncycastleAsn1X509NoticeReference_withLibOrgBouncycastleAsn1X509DisplayText_, noticeRef, explicitText)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfSPUserNotice)
