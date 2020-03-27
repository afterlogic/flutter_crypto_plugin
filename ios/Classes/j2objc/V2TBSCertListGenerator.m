//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/V2TBSCertListGenerator.java
//

#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1UTCTime.h"
#include "AlgorithmIdentifier.h"
#include "Asn1X509Time.h"
#include "CRLReason.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "Extension.h"
#include "Extensions.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "TBSCertList.h"
#include "V2TBSCertListGenerator.h"
#include "X500Name.h"
#include "X509Extensions.h"
#include "X509Name.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleAsn1X509V2TBSCertListGenerator () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signature_;
  LibOrgBouncycastleAsn1X500X500Name *issuer_;
  LibOrgBouncycastleAsn1X509Asn1X509Time *thisUpdate_;
  LibOrgBouncycastleAsn1X509Asn1X509Time *nextUpdate_;
  LibOrgBouncycastleAsn1X509Extensions *extensions_;
  LibOrgBouncycastleAsn1ASN1EncodableVector *crlentries_;
}

- (void)internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
                      withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                          withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)extensions;

+ (LibOrgBouncycastleAsn1ASN1Sequence *)createReasonExtensionWithInt:(jint)reasonCode;

+ (LibOrgBouncycastleAsn1ASN1Sequence *)createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)invalidityDate;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, signature_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, issuer_, LibOrgBouncycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, thisUpdate_, LibOrgBouncycastleAsn1X509Asn1X509Time *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, nextUpdate_, LibOrgBouncycastleAsn1X509Asn1X509Time *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, extensions_, LibOrgBouncycastleAsn1X509Extensions *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, crlentries_, LibOrgBouncycastleAsn1ASN1EncodableVector *)

inline IOSObjectArray *LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_get_reasons(void);
static IOSObjectArray *LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, reasons, IOSObjectArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509Asn1X509Time_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *self, LibOrgBouncycastleAsn1ASN1Integer *userCertificate, LibOrgBouncycastleAsn1X509Asn1X509Time *revocationDate, LibOrgBouncycastleAsn1ASN1Sequence *extensions);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(jint reasonCode);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *invalidityDate);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator)

@implementation LibOrgBouncycastleAsn1X509V2TBSCertListGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)setSignatureWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signature {
  self->signature_ = signature;
}

- (void)setIssuerWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)issuer {
  self->issuer_ = LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((LibOrgBouncycastleAsn1X509X509Name *) nil_chk(issuer)) toASN1Primitive]);
}

- (void)setIssuerWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)issuer {
  self->issuer_ = issuer;
}

- (void)setThisUpdateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)thisUpdate {
  self->thisUpdate_ = new_LibOrgBouncycastleAsn1X509Asn1X509Time_initWithLibOrgBouncycastleAsn1ASN1Primitive_(thisUpdate);
}

- (void)setNextUpdateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)nextUpdate {
  self->nextUpdate_ = new_LibOrgBouncycastleAsn1X509Asn1X509Time_initWithLibOrgBouncycastleAsn1ASN1Primitive_(nextUpdate);
}

- (void)setThisUpdateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)thisUpdate {
  self->thisUpdate_ = thisUpdate;
}

- (void)setNextUpdateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)nextUpdate {
  self->nextUpdate_ = nextUpdate;
}

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)crlEntry {
  [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(crlentries_)) addWithLibOrgBouncycastleAsn1ASN1Encodable:crlEntry];
}

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
                   withLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)revocationDate
                                                 withInt:(jint)reason {
  [self addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:userCertificate withLibOrgBouncycastleAsn1X509Asn1X509Time:new_LibOrgBouncycastleAsn1X509Asn1X509Time_initWithLibOrgBouncycastleAsn1ASN1Primitive_(revocationDate) withInt:reason];
}

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
              withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                                                 withInt:(jint)reason {
  [self addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:userCertificate withLibOrgBouncycastleAsn1X509Asn1X509Time:revocationDate withInt:reason withLibOrgBouncycastleAsn1ASN1GeneralizedTime:nil];
}

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
              withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                                                 withInt:(jint)reason
           withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)invalidityDate {
  if (reason != 0) {
    LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    if (reason < ((IOSObjectArray *) nil_chk(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons))->size_) {
      if (reason < 0) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"invalid reason value: ", reason));
      }
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, reason)];
    }
    else {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(reason)];
    }
    if (invalidityDate != nil) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(invalidityDate)];
    }
    LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509Asn1X509Time_withLibOrgBouncycastleAsn1ASN1Sequence_(self, userCertificate, revocationDate, new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v));
  }
  else if (invalidityDate != nil) {
    LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(invalidityDate)];
    LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509Asn1X509Time_withLibOrgBouncycastleAsn1ASN1Sequence_(self, userCertificate, revocationDate, new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v));
  }
  else {
    [self addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:userCertificate withLibOrgBouncycastleAsn1X509Asn1X509Time:revocationDate withLibOrgBouncycastleAsn1X509Extensions:nil];
  }
}

- (void)internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
                      withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                          withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)extensions {
  LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509Asn1X509Time_withLibOrgBouncycastleAsn1ASN1Sequence_(self, userCertificate, revocationDate, extensions);
}

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
              withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:userCertificate];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:revocationDate];
  if (extensions != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:extensions];
  }
  [self addCRLEntryWithLibOrgBouncycastleAsn1ASN1Sequence:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v)];
}

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509X509Extensions:(LibOrgBouncycastleAsn1X509X509Extensions *)extensions {
  [self setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(extensions)];
}

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions {
  self->extensions_ = extensions;
}

- (LibOrgBouncycastleAsn1X509TBSCertList *)generateTBSCertList {
  if ((signature_ == nil) || (issuer_ == nil) || (thisUpdate_ == nil)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not all mandatory fields set in V2 TBSCertList generator.");
  }
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:signature_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:issuer_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:thisUpdate_];
  if (nextUpdate_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:nextUpdate_];
  }
  if ([((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(crlentries_)) size] != 0) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(crlentries_)];
  }
  if (extensions_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(0, extensions_)];
  }
  return new_LibOrgBouncycastleAsn1X509TBSCertList_initWithLibOrgBouncycastleAsn1ASN1Sequence_(new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v));
}

+ (LibOrgBouncycastleAsn1ASN1Sequence *)createReasonExtensionWithInt:(jint)reasonCode {
  return LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(reasonCode);
}

+ (LibOrgBouncycastleAsn1ASN1Sequence *)createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)invalidityDate {
  return LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(invalidityDate);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 14, 15, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 16, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 18, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 19, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509TBSCertList;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0xa, 20, 21, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0xa, 22, 23, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(setSignatureWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:);
  methods[2].selector = @selector(setIssuerWithLibOrgBouncycastleAsn1X509X509Name:);
  methods[3].selector = @selector(setIssuerWithLibOrgBouncycastleAsn1X500X500Name:);
  methods[4].selector = @selector(setThisUpdateWithLibOrgBouncycastleAsn1ASN1UTCTime:);
  methods[5].selector = @selector(setNextUpdateWithLibOrgBouncycastleAsn1ASN1UTCTime:);
  methods[6].selector = @selector(setThisUpdateWithLibOrgBouncycastleAsn1X509Asn1X509Time:);
  methods[7].selector = @selector(setNextUpdateWithLibOrgBouncycastleAsn1X509Asn1X509Time:);
  methods[8].selector = @selector(addCRLEntryWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[9].selector = @selector(addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1UTCTime:withInt:);
  methods[10].selector = @selector(addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X509Asn1X509Time:withInt:);
  methods[11].selector = @selector(addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X509Asn1X509Time:withInt:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:);
  methods[12].selector = @selector(internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X509Asn1X509Time:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[13].selector = @selector(addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X509Asn1X509Time:withLibOrgBouncycastleAsn1X509Extensions:);
  methods[14].selector = @selector(setExtensionsWithLibOrgBouncycastleAsn1X509X509Extensions:);
  methods[15].selector = @selector(setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:);
  methods[16].selector = @selector(generateTBSCertList);
  methods[17].selector = @selector(createReasonExtensionWithInt:);
  methods[18].selector = @selector(createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 24, -1, -1, -1 },
    { "signature_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "issuer_", "LLibOrgBouncycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "thisUpdate_", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nextUpdate_", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "extensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "crlentries_", "LLibOrgBouncycastleAsn1ASN1EncodableVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reasons", "[LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
  };
  static const void *ptrTable[] = { "setSignature", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", "setIssuer", "LLibOrgBouncycastleAsn1X509X509Name;", "LLibOrgBouncycastleAsn1X500X500Name;", "setThisUpdate", "LLibOrgBouncycastleAsn1ASN1UTCTime;", "setNextUpdate", "LLibOrgBouncycastleAsn1X509Asn1X509Time;", "addCRLEntry", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1UTCTime;I", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X509Asn1X509Time;I", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X509Asn1X509Time;ILLibOrgBouncycastleAsn1ASN1GeneralizedTime;", "internalAddCRLEntry", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X509Asn1X509Time;LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X509Asn1X509Time;LLibOrgBouncycastleAsn1X509Extensions;", "setExtensions", "LLibOrgBouncycastleAsn1X509X509Extensions;", "LLibOrgBouncycastleAsn1X509Extensions;", "createReasonExtension", "I", "createInvalidityDateExtension", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", "version", &LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509V2TBSCertListGenerator = { "V2TBSCertListGenerator", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 19, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509V2TBSCertListGenerator;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1X509V2TBSCertListGenerator class]) {
    {
      LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons = [IOSObjectArray newArrayWithLength:11 type:LibOrgBouncycastleAsn1ASN1Sequence_class_()];
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 0, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_unspecified));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 1, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_keyCompromise));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 2, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_cACompromise));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 3, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_affiliationChanged));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 4, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_superseded));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 5, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_cessationOfOperation));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 6, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_certificateHold));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 7, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(7));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 8, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_removeFromCRL));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 9, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_privilegeWithdrawn));
      (void) IOSObjectArray_Set(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_reasons, 10, LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(LibOrgBouncycastleAsn1X509CRLReason_aACompromise));
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator)
  }
}

@end

void LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_init(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *self) {
  NSObject_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(1);
  self->nextUpdate_ = nil;
  self->extensions_ = nil;
  self->crlentries_ = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
}

LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *new_LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, init)
}

LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *create_LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator, init)
}

void LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_internalAddCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509Asn1X509Time_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *self, LibOrgBouncycastleAsn1ASN1Integer *userCertificate, LibOrgBouncycastleAsn1X509Asn1X509Time *revocationDate, LibOrgBouncycastleAsn1ASN1Sequence *extensions) {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:userCertificate];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:revocationDate];
  if (extensions != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:extensions];
  }
  [self addCRLEntryWithLibOrgBouncycastleAsn1ASN1Sequence:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v)];
}

LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createReasonExtensionWithInt_(jint reasonCode) {
  LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_initialize();
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  LibOrgBouncycastleAsn1X509CRLReason *crlReason = LibOrgBouncycastleAsn1X509CRLReason_lookupWithInt_(reasonCode);
  @try {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, reasonCode)];
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([((LibOrgBouncycastleAsn1X509CRLReason *) nil_chk(crlReason)) getEncoded])];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"error encoding reason: ", e));
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_createInvalidityDateExtensionWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *invalidityDate) {
  LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_initialize();
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  @try {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:JreLoadStatic(LibOrgBouncycastleAsn1X509Extension, invalidityDate)];
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([((LibOrgBouncycastleAsn1ASN1GeneralizedTime *) nil_chk(invalidityDate)) getEncoded])];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"error encoding reason: ", e));
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator)
