//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/CmsAttribute.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1Set.h"
#include "CmsAttribute.h"
#include "DERSequence.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1CmsCmsAttribute () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *attrType_;
  LibOrgBouncycastleAsn1ASN1Set *attrValues_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsCmsAttribute, attrType_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsCmsAttribute, attrValues_, LibOrgBouncycastleAsn1ASN1Set *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsCmsAttribute *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsCmsAttribute *new_LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsCmsAttribute *create_LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmsCmsAttribute

+ (LibOrgBouncycastleAsn1CmsCmsAttribute *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmsCmsAttribute_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)attrType
                                 withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)attrValues {
  LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_(self, attrType, attrValues);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getAttrType {
  return attrType_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getAttrValues {
  return attrValues_;
}

- (IOSObjectArray *)getAttributeValues {
  return [((LibOrgBouncycastleAsn1ASN1Set *) nil_chk(attrValues_)) toArray];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:attrType_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:attrValues_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmsCmsAttribute;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Set:);
  methods[3].selector = @selector(getAttrType);
  methods[4].selector = @selector(getAttrValues);
  methods[5].selector = @selector(getAttributeValues);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "attrType_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "attrValues_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Set;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsCmsAttribute = { "CmsAttribute", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsCmsAttribute;
}

@end

LibOrgBouncycastleAsn1CmsCmsAttribute *LibOrgBouncycastleAsn1CmsCmsAttribute_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmsCmsAttribute_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmsCmsAttribute class]]) {
    return (LibOrgBouncycastleAsn1CmsCmsAttribute *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsCmsAttribute *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->attrType_ = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  self->attrValues_ = (LibOrgBouncycastleAsn1ASN1Set *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1Set class]);
}

LibOrgBouncycastleAsn1CmsCmsAttribute *new_LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsCmsAttribute, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsCmsAttribute *create_LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsCmsAttribute, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsCmsAttribute *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *attrType, LibOrgBouncycastleAsn1ASN1Set *attrValues) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->attrType_ = attrType;
  self->attrValues_ = attrValues;
}

LibOrgBouncycastleAsn1CmsCmsAttribute *new_LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *attrType, LibOrgBouncycastleAsn1ASN1Set *attrValues) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsCmsAttribute, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_, attrType, attrValues)
}

LibOrgBouncycastleAsn1CmsCmsAttribute *create_LibOrgBouncycastleAsn1CmsCmsAttribute_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *attrType, LibOrgBouncycastleAsn1ASN1Set *attrValues) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsCmsAttribute, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_, attrType, attrValues)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsCmsAttribute)
