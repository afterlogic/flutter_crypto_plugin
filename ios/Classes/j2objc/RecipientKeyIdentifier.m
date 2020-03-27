//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/RecipientKeyIdentifier.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OtherKeyAttribute.h"
#include "RecipientKeyIdentifier.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier () {
 @public
  LibOrgBouncycastleAsn1ASN1OctetString *subjectKeyIdentifier_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *date_;
  LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, subjectKeyIdentifier_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, date_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, other_, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *)

@implementation LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)subjectKeyIdentifier
                withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)date
               withLibOrgBouncycastleAsn1CmsOtherKeyAttribute:(LibOrgBouncycastleAsn1CmsOtherKeyAttribute *)other {
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(self, subjectKeyIdentifier, date, other);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)subjectKeyIdentifier
withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)date
withLibOrgBouncycastleAsn1CmsOtherKeyAttribute:(LibOrgBouncycastleAsn1CmsOtherKeyAttribute *)other {
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(self, subjectKeyIdentifier, date, other);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)subjectKeyIdentifier {
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_(self, subjectKeyIdentifier);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)ato
                                                                                               withBoolean:(jboolean)isExplicit {
  return LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(ato, isExplicit);
}

+ (LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getSubjectKeyIdentifier {
  return subjectKeyIdentifier_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getDate {
  return date_;
}

- (LibOrgBouncycastleAsn1CmsOtherKeyAttribute *)getOtherKeyAttribute {
  return other_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:subjectKeyIdentifier_];
  if (date_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:date_];
  }
  if (other_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:other_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier;", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier;", 0x9, 4, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsOtherKeyAttribute;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1OctetString:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1CmsOtherKeyAttribute:);
  methods[1].selector = @selector(initWithByteArray:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1CmsOtherKeyAttribute:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[5].selector = @selector(getInstanceWithId:);
  methods[6].selector = @selector(getSubjectKeyIdentifier);
  methods[7].selector = @selector(getDate);
  methods[8].selector = @selector(getOtherKeyAttribute);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "subjectKeyIdentifier_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "date_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "other_", "LLibOrgBouncycastleAsn1CmsOtherKeyAttribute;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1OctetString;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1CmsOtherKeyAttribute;", "[BLLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1CmsOtherKeyAttribute;", "[B", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier = { "RecipientKeyIdentifier", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier;
}

@end

void LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *self, LibOrgBouncycastleAsn1ASN1OctetString *subjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->subjectKeyIdentifier_ = subjectKeyIdentifier;
  self->date_ = date;
  self->other_ = other;
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *new_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(LibOrgBouncycastleAsn1ASN1OctetString *subjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_, subjectKeyIdentifier, date, other)
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *create_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(LibOrgBouncycastleAsn1ASN1OctetString *subjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_, subjectKeyIdentifier, date, other)
}

void LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *self, IOSByteArray *subjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->subjectKeyIdentifier_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(subjectKeyIdentifier);
  self->date_ = date;
  self->other_ = other;
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *new_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(IOSByteArray *subjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_, subjectKeyIdentifier, date, other)
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *create_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(IOSByteArray *subjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_, subjectKeyIdentifier, date, other)
}

void LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *self, IOSByteArray *subjectKeyIdentifier) {
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(self, subjectKeyIdentifier, nil, nil);
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *new_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_(IOSByteArray *subjectKeyIdentifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithByteArray_, subjectKeyIdentifier)
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *create_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithByteArray_(IOSByteArray *subjectKeyIdentifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithByteArray_, subjectKeyIdentifier)
}

void LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->subjectKeyIdentifier_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  switch ([seq size]) {
    case 1:
    break;
    case 2:
    if ([[seq getObjectAtWithInt:1] isKindOfClass:[LibOrgBouncycastleAsn1ASN1GeneralizedTime class]]) {
      self->date_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([seq getObjectAtWithInt:1]);
    }
    else {
      self->other_ = LibOrgBouncycastleAsn1CmsOtherKeyAttribute_getInstanceWithId_([seq getObjectAtWithInt:2]);
    }
    break;
    case 3:
    self->date_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([seq getObjectAtWithInt:1]);
    self->other_ = LibOrgBouncycastleAsn1CmsOtherKeyAttribute_getInstanceWithId_([seq getObjectAtWithInt:2]);
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid RecipientKeyIdentifier");
  }
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *new_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *create_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *ato, jboolean isExplicit) {
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initialize();
  return LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(ato, isExplicit));
}

LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier class]]) {
    return (LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier)
