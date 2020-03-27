//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/CRLBag.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "CRLBag.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1PkcsCRLBag () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *crlId_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> crlValue_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsCRLBag, crlId_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsCRLBag, crlValue_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsCRLBag *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1PkcsCRLBag *new_LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1PkcsCRLBag *create_LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1PkcsCRLBag

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1PkcsCRLBag *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1PkcsCRLBag_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)crlId
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)crlValue {
  LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, crlId, crlValue);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getCrlId {
  return crlId_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getCrlValue {
  return crlValue_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:crlId_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(0, crlValue_)];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsCRLBag;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[3].selector = @selector(getCrlId);
  methods[4].selector = @selector(getCrlValue);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "crlId_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "crlValue_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1PkcsCRLBag = { "CRLBag", "lib.org.bouncycastle.asn1.pkcs", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1PkcsCRLBag;
}

@end

void LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsCRLBag *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->crlId_ = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  self->crlValue_ = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1TaggedObject class])))) getObject];
}

LibOrgBouncycastleAsn1PkcsCRLBag *new_LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsCRLBag, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1PkcsCRLBag *create_LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsCRLBag, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1PkcsCRLBag *LibOrgBouncycastleAsn1PkcsCRLBag_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1PkcsCRLBag_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1PkcsCRLBag class]]) {
    return (LibOrgBouncycastleAsn1PkcsCRLBag *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1PkcsCRLBag *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *crlId, id<LibOrgBouncycastleAsn1ASN1Encodable> crlValue) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->crlId_ = crlId;
  self->crlValue_ = crlValue;
}

LibOrgBouncycastleAsn1PkcsCRLBag *new_LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *crlId, id<LibOrgBouncycastleAsn1ASN1Encodable> crlValue) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsCRLBag, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, crlId, crlValue)
}

LibOrgBouncycastleAsn1PkcsCRLBag *create_LibOrgBouncycastleAsn1PkcsCRLBag_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *crlId, id<LibOrgBouncycastleAsn1ASN1Encodable> crlValue) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsCRLBag, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, crlId, crlValue)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1PkcsCRLBag)
