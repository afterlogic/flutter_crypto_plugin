//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/V3TBSCertificateGenerator.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1UTCTime.h"
#include "AlgorithmIdentifier.h"
#include "Asn1X509Time.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "Extension.h"
#include "Extensions.h"
#include "J2ObjC_source.h"
#include "SubjectPublicKeyInfo.h"
#include "TBSCertificate.h"
#include "V3TBSCertificateGenerator.h"
#include "X500Name.h"
#include "X509Extensions.h"
#include "X509Name.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator () {
 @public
  jboolean altNamePresentAndCritical_;
  LibOrgBouncycastleAsn1DERBitString *issuerUniqueID_;
  LibOrgBouncycastleAsn1DERBitString *subjectUniqueID_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, issuerUniqueID_, LibOrgBouncycastleAsn1DERBitString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, subjectUniqueID_, LibOrgBouncycastleAsn1DERBitString *)

@implementation LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)setSerialNumberWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serialNumber {
  self->serialNumber_ = serialNumber;
}

- (void)setSignatureWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signature {
  self->signature_ = signature;
}

- (void)setIssuerWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)issuer {
  self->issuer_ = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_(issuer);
}

- (void)setIssuerWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)issuer {
  self->issuer_ = issuer;
}

- (void)setStartDateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)startDate {
  self->startDate_ = new_LibOrgBouncycastleAsn1X509Asn1X509Time_initWithLibOrgBouncycastleAsn1ASN1Primitive_(startDate);
}

- (void)setStartDateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)startDate {
  self->startDate_ = startDate;
}

- (void)setEndDateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)endDate {
  self->endDate_ = new_LibOrgBouncycastleAsn1X509Asn1X509Time_initWithLibOrgBouncycastleAsn1ASN1Primitive_(endDate);
}

- (void)setEndDateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)endDate {
  self->endDate_ = endDate;
}

- (void)setSubjectWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)subject {
  self->subject_ = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((LibOrgBouncycastleAsn1X509X509Name *) nil_chk(subject)) toASN1Primitive]);
}

- (void)setSubjectWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)subject {
  self->subject_ = subject;
}

- (void)setIssuerUniqueIDWithLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)uniqueID {
  self->issuerUniqueID_ = uniqueID;
}

- (void)setSubjectUniqueIDWithLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)uniqueID {
  self->subjectUniqueID_ = uniqueID;
}

- (void)setSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)pubKeyInfo {
  self->subjectPublicKeyInfo_ = pubKeyInfo;
}

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509X509Extensions:(LibOrgBouncycastleAsn1X509X509Extensions *)extensions {
  [self setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(extensions)];
}

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions {
  self->extensions_ = extensions;
  if (extensions != nil) {
    LibOrgBouncycastleAsn1X509Extension *altName = [extensions getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, subjectAlternativeName)];
    if (altName != nil && [altName isCritical]) {
      altNamePresentAndCritical_ = true;
    }
  }
}

- (LibOrgBouncycastleAsn1X509TBSCertificate *)generateTBSCertificate {
  if ((serialNumber_ == nil) || (signature_ == nil) || (issuer_ == nil) || (startDate_ == nil) || (endDate_ == nil) || (subject_ == nil && !altNamePresentAndCritical_) || (subjectPublicKeyInfo_ == nil)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not all mandatory fields set in V3 TBScertificate generator");
  }
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:serialNumber_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:signature_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:issuer_];
  LibOrgBouncycastleAsn1ASN1EncodableVector *validity = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [validity addWithLibOrgBouncycastleAsn1ASN1Encodable:startDate_];
  [validity addWithLibOrgBouncycastleAsn1ASN1Encodable:endDate_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(validity)];
  if (subject_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:subject_];
  }
  else {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_init()];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:subjectPublicKeyInfo_];
  if (issuerUniqueID_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, issuerUniqueID_)];
  }
  if (subjectUniqueID_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 2, subjectUniqueID_)];
  }
  if (extensions_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 3, extensions_)];
  }
  return LibOrgBouncycastleAsn1X509TBSCertificate_getInstanceWithId_(new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 14, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 15, 16, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 18, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 19, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509TBSCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(setSerialNumberWithLibOrgBouncycastleAsn1ASN1Integer:);
  methods[2].selector = @selector(setSignatureWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:);
  methods[3].selector = @selector(setIssuerWithLibOrgBouncycastleAsn1X509X509Name:);
  methods[4].selector = @selector(setIssuerWithLibOrgBouncycastleAsn1X500X500Name:);
  methods[5].selector = @selector(setStartDateWithLibOrgBouncycastleAsn1ASN1UTCTime:);
  methods[6].selector = @selector(setStartDateWithLibOrgBouncycastleAsn1X509Asn1X509Time:);
  methods[7].selector = @selector(setEndDateWithLibOrgBouncycastleAsn1ASN1UTCTime:);
  methods[8].selector = @selector(setEndDateWithLibOrgBouncycastleAsn1X509Asn1X509Time:);
  methods[9].selector = @selector(setSubjectWithLibOrgBouncycastleAsn1X509X509Name:);
  methods[10].selector = @selector(setSubjectWithLibOrgBouncycastleAsn1X500X500Name:);
  methods[11].selector = @selector(setIssuerUniqueIDWithLibOrgBouncycastleAsn1DERBitString:);
  methods[12].selector = @selector(setSubjectUniqueIDWithLibOrgBouncycastleAsn1DERBitString:);
  methods[13].selector = @selector(setSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  methods[14].selector = @selector(setExtensionsWithLibOrgBouncycastleAsn1X509X509Extensions:);
  methods[15].selector = @selector(setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:);
  methods[16].selector = @selector(generateTBSCertificate);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1DERTaggedObject;", .constantValue.asLong = 0, 0x0, 20, -1, -1, -1 },
    { "serialNumber_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "signature_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "issuer_", "LLibOrgBouncycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "startDate_", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "endDate_", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subject_", "LLibOrgBouncycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subjectPublicKeyInfo_", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "extensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "altNamePresentAndCritical_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "issuerUniqueID_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "subjectUniqueID_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "setSerialNumber", "LLibOrgBouncycastleAsn1ASN1Integer;", "setSignature", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", "setIssuer", "LLibOrgBouncycastleAsn1X509X509Name;", "LLibOrgBouncycastleAsn1X500X500Name;", "setStartDate", "LLibOrgBouncycastleAsn1ASN1UTCTime;", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", "setEndDate", "setSubject", "setIssuerUniqueID", "LLibOrgBouncycastleAsn1DERBitString;", "setSubjectUniqueID", "setSubjectPublicKeyInfo", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", "setExtensions", "LLibOrgBouncycastleAsn1X509X509Extensions;", "LLibOrgBouncycastleAsn1X509Extensions;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator = { "V3TBSCertificateGenerator", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 17, 12, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator;
}

@end

void LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator_init(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator *self) {
  NSObject_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(2));
}

LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator *new_LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, init)
}

LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator *create_LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator)
