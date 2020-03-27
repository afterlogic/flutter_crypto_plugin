//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/PKMACValue.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "CMPObjectIdentifiers.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "PBMParameter.h"
#include "PKMACValue.h"

@interface LibOrgBouncycastleAsn1CrmfPKMACValue () {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId_;
  LibOrgBouncycastleAsn1DERBitString *value_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfPKMACValue, algId_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfPKMACValue, value_, LibOrgBouncycastleAsn1DERBitString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CrmfPKMACValue *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfPKMACValue *new_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfPKMACValue *create_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CrmfPKMACValue

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CrmfPKMACValue *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CrmfPKMACValue_getInstanceWithId_(o);
}

+ (LibOrgBouncycastleAsn1CrmfPKMACValue *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)isExplicit {
  return LibOrgBouncycastleAsn1CrmfPKMACValue_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, isExplicit);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmpPBMParameter:(LibOrgBouncycastleAsn1CmpPBMParameter *)params
                       withLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)value {
  LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1CmpPBMParameter_withLibOrgBouncycastleAsn1DERBitString_(self, params, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)aid
                               withLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)value {
  LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(self, aid, value);
  return self;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getAlgId {
  return algId_;
}

- (LibOrgBouncycastleAsn1DERBitString *)getValue {
  return value_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:algId_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:value_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfPKMACValue;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfPKMACValue;", 0x9, 1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CmpPBMParameter:withLibOrgBouncycastleAsn1DERBitString:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1DERBitString:);
  methods[5].selector = @selector(getAlgId);
  methods[6].selector = @selector(getValue);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algId_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "value_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1CmpPBMParameter;LLibOrgBouncycastleAsn1DERBitString;", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1DERBitString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CrmfPKMACValue = { "PKMACValue", "lib.org.bouncycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CrmfPKMACValue;
}

@end

void LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CrmfPKMACValue *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->algId_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->value_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

LibOrgBouncycastleAsn1CrmfPKMACValue *new_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfPKMACValue, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CrmfPKMACValue *create_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfPKMACValue, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CrmfPKMACValue *LibOrgBouncycastleAsn1CrmfPKMACValue_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CrmfPKMACValue_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CrmfPKMACValue class]]) {
    return (LibOrgBouncycastleAsn1CrmfPKMACValue *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

LibOrgBouncycastleAsn1CrmfPKMACValue *LibOrgBouncycastleAsn1CrmfPKMACValue_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean isExplicit) {
  LibOrgBouncycastleAsn1CrmfPKMACValue_initialize();
  return LibOrgBouncycastleAsn1CrmfPKMACValue_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, isExplicit));
}

void LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1CmpPBMParameter_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1CrmfPKMACValue *self, LibOrgBouncycastleAsn1CmpPBMParameter *params, LibOrgBouncycastleAsn1DERBitString *value) {
  LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(self, new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1CmpCMPObjectIdentifiers, passwordBasedMac), params), value);
}

LibOrgBouncycastleAsn1CrmfPKMACValue *new_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1CmpPBMParameter_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1CmpPBMParameter *params, LibOrgBouncycastleAsn1DERBitString *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfPKMACValue, initWithLibOrgBouncycastleAsn1CmpPBMParameter_withLibOrgBouncycastleAsn1DERBitString_, params, value)
}

LibOrgBouncycastleAsn1CrmfPKMACValue *create_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1CmpPBMParameter_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1CmpPBMParameter *params, LibOrgBouncycastleAsn1DERBitString *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfPKMACValue, initWithLibOrgBouncycastleAsn1CmpPBMParameter_withLibOrgBouncycastleAsn1DERBitString_, params, value)
}

void LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1CrmfPKMACValue *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *aid, LibOrgBouncycastleAsn1DERBitString *value) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->algId_ = aid;
  self->value_ = value;
}

LibOrgBouncycastleAsn1CrmfPKMACValue *new_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *aid, LibOrgBouncycastleAsn1DERBitString *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfPKMACValue, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_, aid, value)
}

LibOrgBouncycastleAsn1CrmfPKMACValue *create_LibOrgBouncycastleAsn1CrmfPKMACValue_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *aid, LibOrgBouncycastleAsn1DERBitString *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfPKMACValue, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_, aid, value)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CrmfPKMACValue)