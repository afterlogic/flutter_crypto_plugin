//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/CommitmentTypeQualifier.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "CommitmentTypeQualifier.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeIdentifier_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> qualifier_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)as;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, commitmentTypeIdentifier_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, qualifier_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *self, LibOrgBouncycastleAsn1ASN1Sequence *as);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *new_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *as) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *create_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *as);

@implementation LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)commitmentTypeIdentifier {
  LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, commitmentTypeIdentifier);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)commitmentTypeIdentifier
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)qualifier {
  LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, commitmentTypeIdentifier, qualifier);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)as {
  LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, as);
  return self;
}

+ (LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *)getInstanceWithId:(id)as {
  return LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_getInstanceWithId_(as);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getCommitmentTypeIdentifier {
  return commitmentTypeIdentifier_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getQualifier {
  return qualifier_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *dev = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [dev addWithLibOrgBouncycastleAsn1ASN1Encodable:commitmentTypeIdentifier_];
  if (qualifier_ != nil) {
    [dev addWithLibOrgBouncycastleAsn1ASN1Encodable:qualifier_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(dev);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfCommitmentTypeQualifier;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getCommitmentTypeIdentifier);
  methods[5].selector = @selector(getQualifier);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "commitmentTypeIdentifier_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "qualifier_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier = { "CommitmentTypeQualifier", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier;
}

@end

void LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeIdentifier) {
  LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, commitmentTypeIdentifier, nil);
}

LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *new_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeIdentifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, commitmentTypeIdentifier)
}

LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *create_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeIdentifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, commitmentTypeIdentifier)
}

void LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeIdentifier, id<LibOrgBouncycastleAsn1ASN1Encodable> qualifier) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->commitmentTypeIdentifier_ = commitmentTypeIdentifier;
  self->qualifier_ = qualifier;
}

LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *new_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeIdentifier, id<LibOrgBouncycastleAsn1ASN1Encodable> qualifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, commitmentTypeIdentifier, qualifier)
}

LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *create_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeIdentifier, id<LibOrgBouncycastleAsn1ASN1Encodable> qualifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, commitmentTypeIdentifier, qualifier)
}

void LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *self, LibOrgBouncycastleAsn1ASN1Sequence *as) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->commitmentTypeIdentifier_ = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(as)) getObjectAtWithInt:0], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  if ([as size] > 1) {
    self->qualifier_ = [as getObjectAtWithInt:1];
  }
}

LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *new_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *as) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, initWithLibOrgBouncycastleAsn1ASN1Sequence_, as)
}

LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *create_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *as) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier, initWithLibOrgBouncycastleAsn1ASN1Sequence_, as)
}

LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_getInstanceWithId_(id as) {
  LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initialize();
  if ([as isKindOfClass:[LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier class]]) {
    return (LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier *) as;
  }
  else if (as != nil) {
    return new_LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(as));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfCommitmentTypeQualifier)