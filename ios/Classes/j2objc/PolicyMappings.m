//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/PolicyMappings.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "CertPolicyId.h"
#include "DERSequence.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "PolicyMappings.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"

@interface LibOrgBouncycastleAsn1X509PolicyMappings ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509PolicyMappings *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509PolicyMappings *new_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509PolicyMappings *create_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X509PolicyMappings

+ (LibOrgBouncycastleAsn1X509PolicyMappings *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509PolicyMappings_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithJavaUtilHashtable:(JavaUtilHashtable *)mappings {
  LibOrgBouncycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(self, mappings);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509CertPolicyId:(LibOrgBouncycastleAsn1X509CertPolicyId *)issuerDomainPolicy
                    withLibOrgBouncycastleAsn1X509CertPolicyId:(LibOrgBouncycastleAsn1X509CertPolicyId *)subjectDomainPolicy {
  LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyId_withLibOrgBouncycastleAsn1X509CertPolicyId_(self, issuerDomainPolicy, subjectDomainPolicy);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray:(IOSObjectArray *)issuerDomainPolicy
                    withLibOrgBouncycastleAsn1X509CertPolicyIdArray:(IOSObjectArray *)subjectDomainPolicy {
  LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray_withLibOrgBouncycastleAsn1X509CertPolicyIdArray_(self, issuerDomainPolicy, subjectDomainPolicy);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509PolicyMappings;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithJavaUtilHashtable:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509CertPolicyId:withLibOrgBouncycastleAsn1X509CertPolicyId:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray:withLibOrgBouncycastleAsn1X509CertPolicyIdArray:);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seq_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LJavaUtilHashtable;", "LLibOrgBouncycastleAsn1X509CertPolicyId;LLibOrgBouncycastleAsn1X509CertPolicyId;", "[LLibOrgBouncycastleAsn1X509CertPolicyId;[LLibOrgBouncycastleAsn1X509CertPolicyId;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509PolicyMappings = { "PolicyMappings", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509PolicyMappings;
}

@end

LibOrgBouncycastleAsn1X509PolicyMappings *LibOrgBouncycastleAsn1X509PolicyMappings_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509PolicyMappings_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509PolicyMappings class]]) {
    return (LibOrgBouncycastleAsn1X509PolicyMappings *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509PolicyMappings *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  self->seq_ = seq;
}

LibOrgBouncycastleAsn1X509PolicyMappings *new_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509PolicyMappings *create_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(LibOrgBouncycastleAsn1X509PolicyMappings *self, JavaUtilHashtable *mappings) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  LibOrgBouncycastleAsn1ASN1EncodableVector *dev = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  id<JavaUtilEnumeration> it = [((JavaUtilHashtable *) nil_chk(mappings)) keys];
  while ([((id<JavaUtilEnumeration>) nil_chk(it)) hasMoreElements]) {
    NSString *idp = (NSString *) cast_chk([it nextElement], [NSString class]);
    NSString *sdp = (NSString *) cast_chk([mappings getWithId:idp], [NSString class]);
    LibOrgBouncycastleAsn1ASN1EncodableVector *dv = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    [dv addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(idp)];
    [dv addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(sdp)];
    [dev addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(dv)];
  }
  self->seq_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(dev);
}

LibOrgBouncycastleAsn1X509PolicyMappings *new_LibOrgBouncycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(JavaUtilHashtable *mappings) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithJavaUtilHashtable_, mappings)
}

LibOrgBouncycastleAsn1X509PolicyMappings *create_LibOrgBouncycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(JavaUtilHashtable *mappings) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithJavaUtilHashtable_, mappings)
}

void LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyId_withLibOrgBouncycastleAsn1X509CertPolicyId_(LibOrgBouncycastleAsn1X509PolicyMappings *self, LibOrgBouncycastleAsn1X509CertPolicyId *issuerDomainPolicy, LibOrgBouncycastleAsn1X509CertPolicyId *subjectDomainPolicy) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  LibOrgBouncycastleAsn1ASN1EncodableVector *dv = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [dv addWithLibOrgBouncycastleAsn1ASN1Encodable:issuerDomainPolicy];
  [dv addWithLibOrgBouncycastleAsn1ASN1Encodable:subjectDomainPolicy];
  self->seq_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(dv));
}

LibOrgBouncycastleAsn1X509PolicyMappings *new_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyId_withLibOrgBouncycastleAsn1X509CertPolicyId_(LibOrgBouncycastleAsn1X509CertPolicyId *issuerDomainPolicy, LibOrgBouncycastleAsn1X509CertPolicyId *subjectDomainPolicy) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithLibOrgBouncycastleAsn1X509CertPolicyId_withLibOrgBouncycastleAsn1X509CertPolicyId_, issuerDomainPolicy, subjectDomainPolicy)
}

LibOrgBouncycastleAsn1X509PolicyMappings *create_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyId_withLibOrgBouncycastleAsn1X509CertPolicyId_(LibOrgBouncycastleAsn1X509CertPolicyId *issuerDomainPolicy, LibOrgBouncycastleAsn1X509CertPolicyId *subjectDomainPolicy) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithLibOrgBouncycastleAsn1X509CertPolicyId_withLibOrgBouncycastleAsn1X509CertPolicyId_, issuerDomainPolicy, subjectDomainPolicy)
}

void LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray_withLibOrgBouncycastleAsn1X509CertPolicyIdArray_(LibOrgBouncycastleAsn1X509PolicyMappings *self, IOSObjectArray *issuerDomainPolicy, IOSObjectArray *subjectDomainPolicy) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  LibOrgBouncycastleAsn1ASN1EncodableVector *dev = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(issuerDomainPolicy))->size_; i++) {
    LibOrgBouncycastleAsn1ASN1EncodableVector *dv = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    [dv addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(issuerDomainPolicy, i)];
    [dv addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(nil_chk(subjectDomainPolicy), i)];
    [dev addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(dv)];
  }
  self->seq_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(dev);
}

LibOrgBouncycastleAsn1X509PolicyMappings *new_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray_withLibOrgBouncycastleAsn1X509CertPolicyIdArray_(IOSObjectArray *issuerDomainPolicy, IOSObjectArray *subjectDomainPolicy) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray_withLibOrgBouncycastleAsn1X509CertPolicyIdArray_, issuerDomainPolicy, subjectDomainPolicy)
}

LibOrgBouncycastleAsn1X509PolicyMappings *create_LibOrgBouncycastleAsn1X509PolicyMappings_initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray_withLibOrgBouncycastleAsn1X509CertPolicyIdArray_(IOSObjectArray *issuerDomainPolicy, IOSObjectArray *subjectDomainPolicy) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509PolicyMappings, initWithLibOrgBouncycastleAsn1X509CertPolicyIdArray_withLibOrgBouncycastleAsn1X509CertPolicyIdArray_, issuerDomainPolicy, subjectDomainPolicy)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509PolicyMappings)
