//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/EncryptedPrivateKeyInfo.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "EncryptedPrivateKeyInfo.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo () {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId_;
  LibOrgBouncycastleAsn1ASN1OctetString *data_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo, algId_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo, data_, LibOrgBouncycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *new_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *create_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                        withByteArray:(IOSByteArray *)encoding {
  LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(self, algId, encoding);
  return self;
}

+ (LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getEncryptionAlgorithm {
  return algId_;
}

- (IOSByteArray *)getEncryptedData {
  return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(data_)) getOctets];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:algId_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:data_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withByteArray:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getEncryptionAlgorithm);
  methods[4].selector = @selector(getEncryptedData);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algId_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "data_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;[B", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo = { "EncryptedPrivateKeyInfo", "lib.org.bouncycastle.asn1.pkcs", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo;
}

@end

void LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->algId_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  self->data_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([e nextElement]);
}

LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *new_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *create_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *encoding) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->algId_ = algId;
  self->data_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(encoding);
}

LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *new_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_, algId, encoding)
}

LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *create_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_, algId, encoding)
}

LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo class]]) {
    return (LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo)