//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/Signature.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"
#include "Signature.h"

@interface LibOrgBouncycastleAsn1OcspSignature ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspSignature *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspSignature *new_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspSignature *create_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1OcspSignature

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signatureAlgorithm
                               withLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)signature {
  LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(self, signatureAlgorithm, signature);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signatureAlgorithm
                               withLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)signature
                               withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)certs {
  LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Sequence_(self, signatureAlgorithm, signature, certs);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1OcspSignature *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                   withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1OcspSignature_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1OcspSignature *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1OcspSignature_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSignatureAlgorithm {
  return signatureAlgorithm_;
}

- (LibOrgBouncycastleAsn1DERBitString *)getSignature {
  return signature_;
}

- (LibOrgBouncycastleAsn1ASN1Sequence *)getCerts {
  return certs_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:signatureAlgorithm_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:signature_];
  if (certs_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, certs_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspSignature;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspSignature;", 0x9, 3, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1DERBitString:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1DERBitString:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getSignatureAlgorithm);
  methods[6].selector = @selector(getSignature);
  methods[7].selector = @selector(getCerts);
  methods[8].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "signatureAlgorithm_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "signature_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "certs_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1DERBitString;", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1DERBitString;LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1OcspSignature = { "Signature", "lib.org.bouncycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1OcspSignature;
}

@end

void LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1OcspSignature *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, LibOrgBouncycastleAsn1DERBitString *signature) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->signatureAlgorithm_ = signatureAlgorithm;
  self->signature_ = signature;
}

LibOrgBouncycastleAsn1OcspSignature *new_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, LibOrgBouncycastleAsn1DERBitString *signature) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspSignature, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_, signatureAlgorithm, signature)
}

LibOrgBouncycastleAsn1OcspSignature *create_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, LibOrgBouncycastleAsn1DERBitString *signature) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspSignature, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_, signatureAlgorithm, signature)
}

void LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspSignature *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, LibOrgBouncycastleAsn1DERBitString *signature, LibOrgBouncycastleAsn1ASN1Sequence *certs) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->signatureAlgorithm_ = signatureAlgorithm;
  self->signature_ = signature;
  self->certs_ = certs;
}

LibOrgBouncycastleAsn1OcspSignature *new_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, LibOrgBouncycastleAsn1DERBitString *signature, LibOrgBouncycastleAsn1ASN1Sequence *certs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspSignature, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Sequence_, signatureAlgorithm, signature, certs)
}

LibOrgBouncycastleAsn1OcspSignature *create_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, LibOrgBouncycastleAsn1DERBitString *signature, LibOrgBouncycastleAsn1ASN1Sequence *certs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspSignature, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Sequence_, signatureAlgorithm, signature, certs)
}

void LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspSignature *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->signatureAlgorithm_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->signature_ = (LibOrgBouncycastleAsn1DERBitString *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1DERBitString class]);
  if ([seq size] == 3) {
    self->certs_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:2], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true);
  }
}

LibOrgBouncycastleAsn1OcspSignature *new_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspSignature, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspSignature *create_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspSignature, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspSignature *LibOrgBouncycastleAsn1OcspSignature_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1OcspSignature_initialize();
  return LibOrgBouncycastleAsn1OcspSignature_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1OcspSignature *LibOrgBouncycastleAsn1OcspSignature_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1OcspSignature_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1OcspSignature class]]) {
    return (LibOrgBouncycastleAsn1OcspSignature *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1OcspSignature_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1OcspSignature)