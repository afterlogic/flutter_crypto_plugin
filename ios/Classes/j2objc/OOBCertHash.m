//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/OOBCertHash.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "CertId.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OOBCertHash.h"

@interface LibOrgBouncycastleAsn1CmpOOBCertHash () {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlg_;
  LibOrgBouncycastleAsn1CrmfCertId *certId_;
  LibOrgBouncycastleAsn1DERBitString *hashVal_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                                                         withInt:(jint)tagNo
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpOOBCertHash, hashAlg_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpOOBCertHash, certId_, LibOrgBouncycastleAsn1CrmfCertId *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpOOBCertHash, hashVal_, LibOrgBouncycastleAsn1DERBitString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpOOBCertHash *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpOOBCertHash *new_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpOOBCertHash *create_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpOOBCertHash_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpOOBCertHash *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

@implementation LibOrgBouncycastleAsn1CmpOOBCertHash

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpOOBCertHash *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpOOBCertHash_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)hashAlg
                                 withLibOrgBouncycastleAsn1CrmfCertId:(LibOrgBouncycastleAsn1CrmfCertId *)certId
                                                        withByteArray:(IOSByteArray *)hashVal {
  LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withByteArray_(self, hashAlg, certId, hashVal);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)hashAlg
                                 withLibOrgBouncycastleAsn1CrmfCertId:(LibOrgBouncycastleAsn1CrmfCertId *)certId
                               withLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)hashVal {
  LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withLibOrgBouncycastleAsn1DERBitString_(self, hashAlg, certId, hashVal);
  return self;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getHashAlg {
  return hashAlg_;
}

- (LibOrgBouncycastleAsn1CrmfCertId *)getCertId {
  return certId_;
}

- (LibOrgBouncycastleAsn1DERBitString *)getHashVal {
  return hashVal_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  LibOrgBouncycastleAsn1CmpOOBCertHash_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 0, hashAlg_);
  LibOrgBouncycastleAsn1CmpOOBCertHash_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 1, certId_);
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:hashVal_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                                                         withInt:(jint)tagNo
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1CmpOOBCertHash_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, tagNo, obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpOOBCertHash;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfCertId;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1CrmfCertId:withByteArray:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1CrmfCertId:withLibOrgBouncycastleAsn1DERBitString:);
  methods[4].selector = @selector(getHashAlg);
  methods[5].selector = @selector(getCertId);
  methods[6].selector = @selector(getHashVal);
  methods[7].selector = @selector(toASN1Primitive);
  methods[8].selector = @selector(addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:withInt:withLibOrgBouncycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "hashAlg_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certId_", "LLibOrgBouncycastleAsn1CrmfCertId;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashVal_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1CrmfCertId;[B", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1CrmfCertId;LLibOrgBouncycastleAsn1DERBitString;", "addOptional", "LLibOrgBouncycastleAsn1ASN1EncodableVector;ILLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpOOBCertHash = { "OOBCertHash", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpOOBCertHash;
}

@end

void LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpOOBCertHash *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  jint index = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] - 1;
  self->hashVal_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_([seq getObjectAtWithInt:index--]);
  for (jint i = index; i >= 0; i--) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *tObj = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:i], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
    if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(tObj)) getTagNo] == 0) {
      self->hashAlg_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
    }
    else {
      self->certId_ = LibOrgBouncycastleAsn1CrmfCertId_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tObj, true);
    }
  }
}

LibOrgBouncycastleAsn1CmpOOBCertHash *new_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpOOBCertHash, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpOOBCertHash *create_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpOOBCertHash, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpOOBCertHash *LibOrgBouncycastleAsn1CmpOOBCertHash_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpOOBCertHash_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpOOBCertHash class]]) {
    return (LibOrgBouncycastleAsn1CmpOOBCertHash *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withByteArray_(LibOrgBouncycastleAsn1CmpOOBCertHash *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlg, LibOrgBouncycastleAsn1CrmfCertId *certId, IOSByteArray *hashVal) {
  LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withLibOrgBouncycastleAsn1DERBitString_(self, hashAlg, certId, new_LibOrgBouncycastleAsn1DERBitString_initWithByteArray_(hashVal));
}

LibOrgBouncycastleAsn1CmpOOBCertHash *new_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlg, LibOrgBouncycastleAsn1CrmfCertId *certId, IOSByteArray *hashVal) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpOOBCertHash, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withByteArray_, hashAlg, certId, hashVal)
}

LibOrgBouncycastleAsn1CmpOOBCertHash *create_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlg, LibOrgBouncycastleAsn1CrmfCertId *certId, IOSByteArray *hashVal) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpOOBCertHash, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withByteArray_, hashAlg, certId, hashVal)
}

void LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1CmpOOBCertHash *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlg, LibOrgBouncycastleAsn1CrmfCertId *certId, LibOrgBouncycastleAsn1DERBitString *hashVal) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->hashAlg_ = hashAlg;
  self->certId_ = certId;
  self->hashVal_ = hashVal;
}

LibOrgBouncycastleAsn1CmpOOBCertHash *new_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlg, LibOrgBouncycastleAsn1CrmfCertId *certId, LibOrgBouncycastleAsn1DERBitString *hashVal) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpOOBCertHash, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withLibOrgBouncycastleAsn1DERBitString_, hashAlg, certId, hashVal)
}

LibOrgBouncycastleAsn1CmpOOBCertHash *create_LibOrgBouncycastleAsn1CmpOOBCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withLibOrgBouncycastleAsn1DERBitString_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlg, LibOrgBouncycastleAsn1CrmfCertId *certId, LibOrgBouncycastleAsn1DERBitString *hashVal) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpOOBCertHash, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CrmfCertId_withLibOrgBouncycastleAsn1DERBitString_, hashAlg, certId, hashVal)
}

void LibOrgBouncycastleAsn1CmpOOBCertHash_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpOOBCertHash *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  if (obj != nil) {
    [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, tagNo, obj)];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpOOBCertHash)