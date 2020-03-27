//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/TBSCertificate.java
//

#include "ASN1Encodable.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "Asn1X509Time.h"
#include "DERBitString.h"
#include "Extensions.h"
#include "J2ObjC_source.h"
#include "SubjectPublicKeyInfo.h"
#include "TBSCertificate.h"
#include "X500Name.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1X509TBSCertificate ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509TBSCertificate *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509TBSCertificate *new_LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509TBSCertificate *create_LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X509TBSCertificate

+ (LibOrgBouncycastleAsn1X509TBSCertificate *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X509TBSCertificate_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X509TBSCertificate *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509TBSCertificate_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (jint)getVersionNumber {
  return [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(version__)) getValue])) intValue] + 1;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerialNumber {
  return serialNumber_;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSignature {
  return signature_;
}

- (LibOrgBouncycastleAsn1X500X500Name *)getIssuer {
  return issuer_;
}

- (LibOrgBouncycastleAsn1X509Asn1X509Time *)getStartDate {
  return startDate_;
}

- (LibOrgBouncycastleAsn1X509Asn1X509Time *)getEndDate {
  return endDate_;
}

- (LibOrgBouncycastleAsn1X500X500Name *)getSubject {
  return subject_;
}

- (LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)getSubjectPublicKeyInfo {
  return subjectPublicKeyInfo_;
}

- (LibOrgBouncycastleAsn1DERBitString *)getIssuerUniqueId {
  return issuerUniqueId_;
}

- (LibOrgBouncycastleAsn1DERBitString *)getSubjectUniqueId {
  return subjectUniqueId_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions {
  return extensions_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509TBSCertificate;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509TBSCertificate;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Asn1X509Time;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Asn1X509Time;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getVersionNumber);
  methods[4].selector = @selector(getVersion);
  methods[5].selector = @selector(getSerialNumber);
  methods[6].selector = @selector(getSignature);
  methods[7].selector = @selector(getIssuer);
  methods[8].selector = @selector(getStartDate);
  methods[9].selector = @selector(getEndDate);
  methods[10].selector = @selector(getSubject);
  methods[11].selector = @selector(getSubjectPublicKeyInfo);
  methods[12].selector = @selector(getIssuerUniqueId);
  methods[13].selector = @selector(getSubjectUniqueId);
  methods[14].selector = @selector(getExtensions);
  methods[15].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seq_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, 4, -1, -1, -1 },
    { "serialNumber_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "signature_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "issuer_", "LLibOrgBouncycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "startDate_", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "endDate_", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subject_", "LLibOrgBouncycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subjectPublicKeyInfo_", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "issuerUniqueId_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subjectUniqueId_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "extensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509TBSCertificate = { "TBSCertificate", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 16, 12, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509TBSCertificate;
}

@end

LibOrgBouncycastleAsn1X509TBSCertificate *LibOrgBouncycastleAsn1X509TBSCertificate_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X509TBSCertificate_initialize();
  return LibOrgBouncycastleAsn1X509TBSCertificate_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X509TBSCertificate *LibOrgBouncycastleAsn1X509TBSCertificate_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509TBSCertificate_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509TBSCertificate class]]) {
    return (LibOrgBouncycastleAsn1X509TBSCertificate *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509TBSCertificate *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  jint seqStart = 0;
  self->seq_ = seq;
  if ([[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0] isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    self->version__ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:0], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true);
  }
  else {
    seqStart = -1;
    self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(0);
  }
  jboolean isV1 = false;
  jboolean isV2 = false;
  if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->version__)) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(0)]) {
    isV1 = true;
  }
  else if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->version__)) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(1)]) {
    isV2 = true;
  }
  else if (![((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->version__)) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(2)]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"version number not recognised");
  }
  self->serialNumber_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 1]);
  self->signature_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 2]);
  self->issuer_ = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 3]);
  LibOrgBouncycastleAsn1ASN1Sequence *dates = (LibOrgBouncycastleAsn1ASN1Sequence *) cast_chk([seq getObjectAtWithInt:seqStart + 4], [LibOrgBouncycastleAsn1ASN1Sequence class]);
  self->startDate_ = LibOrgBouncycastleAsn1X509Asn1X509Time_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(dates)) getObjectAtWithInt:0]);
  self->endDate_ = LibOrgBouncycastleAsn1X509Asn1X509Time_getInstanceWithId_([dates getObjectAtWithInt:1]);
  self->subject_ = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 5]);
  self->subjectPublicKeyInfo_ = LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 6]);
  jint extras = [seq size] - (seqStart + 6) - 1;
  if (extras != 0 && isV1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"version 1 certificate contains extra data");
  }
  while (extras > 0) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *extra = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:seqStart + 6 + extras], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
    switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(extra)) getTagNo]) {
      case 1:
      self->issuerUniqueId_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(extra, false);
      break;
      case 2:
      self->subjectUniqueId_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(extra, false);
      break;
      case 3:
      if (isV2) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"version 2 certificate cannot contain extensions");
      }
      self->extensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(extra, true));
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Unknown tag encountered in structure: ", [extra getTagNo]));
    }
    extras--;
  }
}

LibOrgBouncycastleAsn1X509TBSCertificate *new_LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509TBSCertificate, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509TBSCertificate *create_LibOrgBouncycastleAsn1X509TBSCertificate_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509TBSCertificate, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509TBSCertificate)
