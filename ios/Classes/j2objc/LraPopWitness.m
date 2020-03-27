//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/LraPopWitness.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "BodyPartID.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "LraPopWitness.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcLraPopWitness () {
 @public
  LibOrgBouncycastleAsn1CmcBodyPartID *pkiDataBodyid_;
  LibOrgBouncycastleAsn1ASN1Sequence *bodyIds_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcLraPopWitness, pkiDataBodyid_, LibOrgBouncycastleAsn1CmcBodyPartID *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcLraPopWitness, bodyIds_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcLraPopWitness *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcLraPopWitness *new_LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcLraPopWitness *create_LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmcLraPopWitness

- (instancetype)initWithLibOrgBouncycastleAsn1CmcBodyPartID:(LibOrgBouncycastleAsn1CmcBodyPartID *)pkiDataBodyid
                     withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)bodyIds {
  LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1Sequence_(self, pkiDataBodyid, bodyIds);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcLraPopWitness *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmcLraPopWitness_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1CmcBodyPartID *)getPkiDataBodyid {
  return pkiDataBodyid_;
}

- (IOSObjectArray *)getBodyIds {
  IOSObjectArray *rv = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(bodyIds_)) size] type:LibOrgBouncycastleAsn1CmcBodyPartID_class_()];
  for (jint i = 0; i != [bodyIds_ size]; i++) {
    (void) IOSObjectArray_Set(rv, i, LibOrgBouncycastleAsn1CmcBodyPartID_getInstanceWithId_([bodyIds_ getObjectAtWithInt:i]));
  }
  return rv;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:pkiDataBodyid_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:bodyIds_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcLraPopWitness;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcBodyPartID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CmcBodyPartID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmcBodyPartID:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getPkiDataBodyid);
  methods[4].selector = @selector(getBodyIds);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "pkiDataBodyid_", "LLibOrgBouncycastleAsn1CmcBodyPartID;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "bodyIds_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmcBodyPartID;LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcLraPopWitness = { "LraPopWitness", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcLraPopWitness;
}

@end

void LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcLraPopWitness *self, LibOrgBouncycastleAsn1CmcBodyPartID *pkiDataBodyid, LibOrgBouncycastleAsn1ASN1Sequence *bodyIds) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->pkiDataBodyid_ = pkiDataBodyid;
  self->bodyIds_ = bodyIds;
}

LibOrgBouncycastleAsn1CmcLraPopWitness *new_LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcBodyPartID *pkiDataBodyid, LibOrgBouncycastleAsn1ASN1Sequence *bodyIds) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcLraPopWitness, initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1Sequence_, pkiDataBodyid, bodyIds)
}

LibOrgBouncycastleAsn1CmcLraPopWitness *create_LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcBodyPartID *pkiDataBodyid, LibOrgBouncycastleAsn1ASN1Sequence *bodyIds) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcLraPopWitness, initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1Sequence_, pkiDataBodyid, bodyIds)
}

void LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcLraPopWitness *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->pkiDataBodyid_ = LibOrgBouncycastleAsn1CmcBodyPartID_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->bodyIds_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

LibOrgBouncycastleAsn1CmcLraPopWitness *new_LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcLraPopWitness, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcLraPopWitness *create_LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcLraPopWitness, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcLraPopWitness *LibOrgBouncycastleAsn1CmcLraPopWitness_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmcLraPopWitness_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmcLraPopWitness class]]) {
    return (LibOrgBouncycastleAsn1CmcLraPopWitness *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmcLraPopWitness_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcLraPopWitness)
