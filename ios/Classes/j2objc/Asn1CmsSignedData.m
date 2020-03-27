//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/Asn1CmsSignedData.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1Set.h"
#include "ASN1TaggedObject.h"
#include "Asn1CmsContentInfo.h"
#include "Asn1CmsSignedData.h"
#include "Asn1CmsSignerInfo.h"
#include "BERSequence.h"
#include "BERSet.h"
#include "BERTaggedObject.h"
#include "CMSObjectIdentifiers.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1CmsAsn1CmsSignedData () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1ASN1Set *digestAlgorithms_;
  LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo_;
  LibOrgBouncycastleAsn1ASN1Set *certificates_;
  LibOrgBouncycastleAsn1ASN1Set *crls_;
  LibOrgBouncycastleAsn1ASN1Set *signerInfos_;
  jboolean certsBer_;
  jboolean crlsBer_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)calculateVersionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)contentOid
                                                                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)certs
                                                                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)crls
                                                                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)signerInfs;

- (jboolean)checkForVersion3WithLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)signerInfs;

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, digestAlgorithms_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, contentInfo_, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, certificates_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, crls_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, signerInfos_, LibOrgBouncycastleAsn1ASN1Set *)

inline LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_get_VERSION_1(void);
static LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_1;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, VERSION_1, LibOrgBouncycastleAsn1ASN1Integer *)

inline LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_get_VERSION_3(void);
static LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_3;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, VERSION_3, LibOrgBouncycastleAsn1ASN1Integer *)

inline LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_get_VERSION_4(void);
static LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_4;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, VERSION_4, LibOrgBouncycastleAsn1ASN1Integer *)

inline LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_get_VERSION_5(void);
static LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_5;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, VERSION_5, LibOrgBouncycastleAsn1ASN1Integer *)

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_calculateVersionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *contentOid, LibOrgBouncycastleAsn1ASN1Set *certs, LibOrgBouncycastleAsn1ASN1Set *crls, LibOrgBouncycastleAsn1ASN1Set *signerInfs);

__attribute__((unused)) static jboolean LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_checkForVersion3WithLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *self, LibOrgBouncycastleAsn1ASN1Set *signerInfs);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *new_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *create_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData)

@implementation LibOrgBouncycastleAsn1CmsAsn1CmsSignedData

+ (LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)digestAlgorithms
      withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)contentInfo
                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)certificates
                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)crls
                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)signerInfos {
  LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(self, digestAlgorithms, contentInfo, certificates, crls, signerInfos);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)calculateVersionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)contentOid
                                                                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)certs
                                                                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)crls
                                                                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)signerInfs {
  return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_calculateVersionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(self, contentOid, certs, crls, signerInfs);
}

- (jboolean)checkForVersion3WithLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)signerInfs {
  return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_checkForVersion3WithLibOrgBouncycastleAsn1ASN1Set_(self, signerInfs);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getDigestAlgorithms {
  return digestAlgorithms_;
}

- (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getEncapContentInfo {
  return contentInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getCertificates {
  return certificates_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getCRLs {
  return crls_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getSignerInfos {
  return signerInfos_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:digestAlgorithms_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:contentInfo_];
  if (certificates_ != nil) {
    if (certsBer_) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1BERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, certificates_)];
    }
    else {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, certificates_)];
    }
  }
  if (crls_ != nil) {
    if (crlsBer_) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1BERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, crls_)];
    }
    else {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, crls_)];
    }
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:signerInfos_];
  return new_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmsAsn1CmsSignedData;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x2, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 5, 6, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1ASN1Set:);
  methods[2].selector = @selector(calculateVersionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1ASN1Set:);
  methods[3].selector = @selector(checkForVersion3WithLibOrgBouncycastleAsn1ASN1Set:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(getVersion);
  methods[6].selector = @selector(getDigestAlgorithms);
  methods[7].selector = @selector(getEncapContentInfo);
  methods[8].selector = @selector(getCertificates);
  methods[9].selector = @selector(getCRLs);
  methods[10].selector = @selector(getSignerInfos);
  methods[11].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "VERSION_1", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x1a, -1, 8, -1, -1 },
    { "VERSION_3", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x1a, -1, 9, -1, -1 },
    { "VERSION_4", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x1a, -1, 10, -1, -1 },
    { "VERSION_5", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x1a, -1, 11, -1, -1 },
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 12, -1, -1, -1 },
    { "digestAlgorithms_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "contentInfo_", "LLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certificates_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "crls_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signerInfos_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certsBer_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "crlsBer_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1ASN1Set;", "calculateVersion", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1ASN1Set;", "checkForVersion3", "LLibOrgBouncycastleAsn1ASN1Set;", "LLibOrgBouncycastleAsn1ASN1Sequence;", &LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_1, &LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_3, &LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_4, &LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_5, "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsAsn1CmsSignedData = { "Asn1CmsSignedData", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 12, 12, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1CmsAsn1CmsSignedData class]) {
    LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_1 = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(1);
    LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_3 = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(3);
    LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_4 = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(4);
    LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_5 = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(5);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData)
  }
}

@end

LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmsAsn1CmsSignedData class]]) {
    return (LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *self, LibOrgBouncycastleAsn1ASN1Set *digestAlgorithms, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo, LibOrgBouncycastleAsn1ASN1Set *certificates, LibOrgBouncycastleAsn1ASN1Set *crls, LibOrgBouncycastleAsn1ASN1Set *signerInfos) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_calculateVersionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(self, [((LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *) nil_chk(contentInfo)) getContentType], certificates, crls, signerInfos);
  self->digestAlgorithms_ = digestAlgorithms;
  self->contentInfo_ = contentInfo;
  self->certificates_ = certificates;
  self->crls_ = crls;
  self->signerInfos_ = signerInfos;
  self->crlsBer_ = [crls isKindOfClass:[LibOrgBouncycastleAsn1BERSet class]];
  self->certsBer_ = [certificates isKindOfClass:[LibOrgBouncycastleAsn1BERSet class]];
}

LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *new_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Set *digestAlgorithms, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo, LibOrgBouncycastleAsn1ASN1Set *certificates, LibOrgBouncycastleAsn1ASN1Set *crls, LibOrgBouncycastleAsn1ASN1Set *signerInfos) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, initWithLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_, digestAlgorithms, contentInfo, certificates, crls, signerInfos)
}

LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *create_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Set *digestAlgorithms, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo, LibOrgBouncycastleAsn1ASN1Set *certificates, LibOrgBouncycastleAsn1ASN1Set *crls, LibOrgBouncycastleAsn1ASN1Set *signerInfos) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, initWithLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_, digestAlgorithms, contentInfo, certificates, crls, signerInfos)
}

LibOrgBouncycastleAsn1ASN1Integer *LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_calculateVersionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *contentOid, LibOrgBouncycastleAsn1ASN1Set *certs, LibOrgBouncycastleAsn1ASN1Set *crls, LibOrgBouncycastleAsn1ASN1Set *signerInfs) {
  jboolean otherCert = false;
  jboolean otherCrl = false;
  jboolean attrCertV1Found = false;
  jboolean attrCertV2Found = false;
  if (certs != nil) {
    for (id<JavaUtilEnumeration> en = [certs getObjects]; [((id<JavaUtilEnumeration>) nil_chk(en)) hasMoreElements]; ) {
      id obj = [en nextElement];
      if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
        LibOrgBouncycastleAsn1ASN1TaggedObject *tagged = LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_(obj);
        if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo] == 1) {
          attrCertV1Found = true;
        }
        else if ([tagged getTagNo] == 2) {
          attrCertV2Found = true;
        }
        else if ([tagged getTagNo] == 3) {
          otherCert = true;
        }
      }
    }
  }
  if (otherCert) {
    return new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(5);
  }
  if (crls != nil) {
    for (id<JavaUtilEnumeration> en = [crls getObjects]; [((id<JavaUtilEnumeration>) nil_chk(en)) hasMoreElements]; ) {
      id obj = [en nextElement];
      if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
        otherCrl = true;
      }
    }
  }
  if (otherCrl) {
    return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_5;
  }
  if (attrCertV2Found) {
    return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_4;
  }
  if (attrCertV1Found) {
    return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_3;
  }
  if (LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_checkForVersion3WithLibOrgBouncycastleAsn1ASN1Set_(self, signerInfs)) {
    return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_3;
  }
  if (![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1CmsCMSObjectIdentifiers, data))) isEqual:contentOid]) {
    return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_3;
  }
  return LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_VERSION_1;
}

jboolean LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_checkForVersion3WithLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *self, LibOrgBouncycastleAsn1ASN1Set *signerInfs) {
  for (id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Set *) nil_chk(signerInfs)) getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
    LibOrgBouncycastleAsn1CmsAsn1CmsSignerInfo *s = LibOrgBouncycastleAsn1CmsAsn1CmsSignerInfo_getInstanceWithId_([e nextElement]);
    if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk([((LibOrgBouncycastleAsn1CmsAsn1CmsSignerInfo *) nil_chk(s)) getVersion])) getValue])) intValue] == 3) {
      return true;
    }
  }
  return false;
}

void LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->version__ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  self->digestAlgorithms_ = ((LibOrgBouncycastleAsn1ASN1Set *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Set class]));
  self->contentInfo_ = LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_getInstanceWithId_([e nextElement]);
  while ([e hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1Primitive *o = (LibOrgBouncycastleAsn1ASN1Primitive *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Primitive class]);
    if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
      LibOrgBouncycastleAsn1ASN1TaggedObject *tagged = (LibOrgBouncycastleAsn1ASN1TaggedObject *) o;
      switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo]) {
        case 0:
        self->certsBer_ = [tagged isKindOfClass:[LibOrgBouncycastleAsn1BERTaggedObject class]];
        self->certificates_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false);
        break;
        case 1:
        self->crlsBer_ = [tagged isKindOfClass:[LibOrgBouncycastleAsn1BERTaggedObject class]];
        self->crls_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false);
        break;
        default:
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown tag value ", [tagged getTagNo]));
      }
    }
    else {
      self->signerInfos_ = (LibOrgBouncycastleAsn1ASN1Set *) cast_chk(o, [LibOrgBouncycastleAsn1ASN1Set class]);
    }
  }
}

LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *new_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsAsn1CmsSignedData *create_LibOrgBouncycastleAsn1CmsAsn1CmsSignedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsAsn1CmsSignedData)
