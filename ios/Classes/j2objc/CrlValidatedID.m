//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/CrlValidatedID.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "CrlIdentifier.h"
#include "CrlValidatedID.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "OtherHash.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1EsfCrlValidatedID () {
 @public
  LibOrgBouncycastleAsn1EsfOtherHash *crlHash_;
  LibOrgBouncycastleAsn1EsfCrlIdentifier *crlIdentifier_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCrlValidatedID, crlHash_, LibOrgBouncycastleAsn1EsfOtherHash *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCrlValidatedID, crlIdentifier_, LibOrgBouncycastleAsn1EsfCrlIdentifier *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCrlValidatedID *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCrlValidatedID *new_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCrlValidatedID *create_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EsfCrlValidatedID

+ (LibOrgBouncycastleAsn1EsfCrlValidatedID *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfCrlValidatedID_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1EsfOtherHash:(LibOrgBouncycastleAsn1EsfOtherHash *)crlHash {
  LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_(self, crlHash);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1EsfOtherHash:(LibOrgBouncycastleAsn1EsfOtherHash *)crlHash
                withLibOrgBouncycastleAsn1EsfCrlIdentifier:(LibOrgBouncycastleAsn1EsfCrlIdentifier *)crlIdentifier {
  LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(self, crlHash, crlIdentifier);
  return self;
}

- (LibOrgBouncycastleAsn1EsfOtherHash *)getCrlHash {
  return self->crlHash_;
}

- (LibOrgBouncycastleAsn1EsfCrlIdentifier *)getCrlIdentifier {
  return self->crlIdentifier_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:[((LibOrgBouncycastleAsn1EsfOtherHash *) nil_chk(self->crlHash_)) toASN1Primitive]];
  if (nil != self->crlIdentifier_) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:[self->crlIdentifier_ toASN1Primitive]];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EsfCrlValidatedID;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfOtherHash;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfCrlIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1EsfOtherHash:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1EsfOtherHash:withLibOrgBouncycastleAsn1EsfCrlIdentifier:);
  methods[4].selector = @selector(getCrlHash);
  methods[5].selector = @selector(getCrlIdentifier);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "crlHash_", "LLibOrgBouncycastleAsn1EsfOtherHash;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "crlIdentifier_", "LLibOrgBouncycastleAsn1EsfCrlIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1EsfOtherHash;", "LLibOrgBouncycastleAsn1EsfOtherHash;LLibOrgBouncycastleAsn1EsfCrlIdentifier;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfCrlValidatedID = { "CrlValidatedID", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfCrlValidatedID;
}

@end

LibOrgBouncycastleAsn1EsfCrlValidatedID *LibOrgBouncycastleAsn1EsfCrlValidatedID_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfCrlValidatedID_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EsfCrlValidatedID class]]) {
    return (LibOrgBouncycastleAsn1EsfCrlValidatedID *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCrlValidatedID *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1 || [seq size] > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->crlHash_ = LibOrgBouncycastleAsn1EsfOtherHash_getInstanceWithId_([seq getObjectAtWithInt:0]);
  if ([seq size] > 1) {
    self->crlIdentifier_ = LibOrgBouncycastleAsn1EsfCrlIdentifier_getInstanceWithId_([seq getObjectAtWithInt:1]);
  }
}

LibOrgBouncycastleAsn1EsfCrlValidatedID *new_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCrlValidatedID, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfCrlValidatedID *create_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCrlValidatedID, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_(LibOrgBouncycastleAsn1EsfCrlValidatedID *self, LibOrgBouncycastleAsn1EsfOtherHash *crlHash) {
  LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(self, crlHash, nil);
}

LibOrgBouncycastleAsn1EsfCrlValidatedID *new_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCrlValidatedID, initWithLibOrgBouncycastleAsn1EsfOtherHash_, crlHash)
}

LibOrgBouncycastleAsn1EsfCrlValidatedID *create_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCrlValidatedID, initWithLibOrgBouncycastleAsn1EsfOtherHash_, crlHash)
}

void LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(LibOrgBouncycastleAsn1EsfCrlValidatedID *self, LibOrgBouncycastleAsn1EsfOtherHash *crlHash, LibOrgBouncycastleAsn1EsfCrlIdentifier *crlIdentifier) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->crlHash_ = crlHash;
  self->crlIdentifier_ = crlIdentifier;
}

LibOrgBouncycastleAsn1EsfCrlValidatedID *new_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash, LibOrgBouncycastleAsn1EsfCrlIdentifier *crlIdentifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCrlValidatedID, initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_, crlHash, crlIdentifier)
}

LibOrgBouncycastleAsn1EsfCrlValidatedID *create_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash, LibOrgBouncycastleAsn1EsfCrlIdentifier *crlIdentifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCrlValidatedID, initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_, crlHash, crlIdentifier)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfCrlValidatedID)