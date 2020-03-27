//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/PolicyInformation.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "PolicyInformation.h"
#include "PolicyQualifierInfo.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/StringBuffer.h"

@interface LibOrgBouncycastleAsn1X509PolicyInformation () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyIdentifier_;
  LibOrgBouncycastleAsn1ASN1Sequence *policyQualifiers_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509PolicyInformation, policyIdentifier_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509PolicyInformation, policyQualifiers_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509PolicyInformation *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509PolicyInformation *new_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509PolicyInformation *create_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X509PolicyInformation

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyIdentifier {
  LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, policyIdentifier);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyIdentifier
                            withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)policyQualifiers {
  LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(self, policyIdentifier, policyQualifiers);
  return self;
}

+ (LibOrgBouncycastleAsn1X509PolicyInformation *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509PolicyInformation_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getPolicyIdentifier {
  return policyIdentifier_;
}

- (LibOrgBouncycastleAsn1ASN1Sequence *)getPolicyQualifiers {
  return policyQualifiers_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:policyIdentifier_];
  if (policyQualifiers_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:policyQualifiers_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (NSString *)description {
  JavaLangStringBuffer *sb = new_JavaLangStringBuffer_init();
  (void) [sb appendWithNSString:@"Policy information: "];
  (void) [sb appendWithId:policyIdentifier_];
  if (policyQualifiers_ != nil) {
    JavaLangStringBuffer *p = new_JavaLangStringBuffer_init();
    for (jint i = 0; i < [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(policyQualifiers_)) size]; i++) {
      if ([p java_length] != 0) {
        (void) [p appendWithNSString:@", "];
      }
      (void) [p appendWithId:LibOrgBouncycastleAsn1X509PolicyQualifierInfo_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(policyQualifiers_)) getObjectAtWithInt:i])];
    }
    (void) [sb appendWithNSString:@"["];
    (void) [sb appendWithJavaLangStringBuffer:p];
    (void) [sb appendWithNSString:@"]"];
  }
  return [sb description];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509PolicyInformation;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 5, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getPolicyIdentifier);
  methods[5].selector = @selector(getPolicyQualifiers);
  methods[6].selector = @selector(toASN1Primitive);
  methods[7].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "policyIdentifier_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "policyQualifiers_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "toString" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509PolicyInformation = { "PolicyInformation", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509PolicyInformation;
}

@end

void LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509PolicyInformation *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1 || [seq size] > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->policyIdentifier_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
  if ([seq size] > 1) {
    self->policyQualifiers_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:1]);
  }
}

LibOrgBouncycastleAsn1X509PolicyInformation *new_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509PolicyInformation, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509PolicyInformation *create_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509PolicyInformation, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1X509PolicyInformation *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyIdentifier) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->policyIdentifier_ = policyIdentifier;
}

LibOrgBouncycastleAsn1X509PolicyInformation *new_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyIdentifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509PolicyInformation, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, policyIdentifier)
}

LibOrgBouncycastleAsn1X509PolicyInformation *create_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyIdentifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509PolicyInformation, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, policyIdentifier)
}

void LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509PolicyInformation *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyIdentifier, LibOrgBouncycastleAsn1ASN1Sequence *policyQualifiers) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->policyIdentifier_ = policyIdentifier;
  self->policyQualifiers_ = policyQualifiers;
}

LibOrgBouncycastleAsn1X509PolicyInformation *new_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyIdentifier, LibOrgBouncycastleAsn1ASN1Sequence *policyQualifiers) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509PolicyInformation, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_, policyIdentifier, policyQualifiers)
}

LibOrgBouncycastleAsn1X509PolicyInformation *create_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *policyIdentifier, LibOrgBouncycastleAsn1ASN1Sequence *policyQualifiers) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509PolicyInformation, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_, policyIdentifier, policyQualifiers)
}

LibOrgBouncycastleAsn1X509PolicyInformation *LibOrgBouncycastleAsn1X509PolicyInformation_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509PolicyInformation_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1X509PolicyInformation class]]) {
    return (LibOrgBouncycastleAsn1X509PolicyInformation *) cast_chk(obj, [LibOrgBouncycastleAsn1X509PolicyInformation class]);
  }
  return new_LibOrgBouncycastleAsn1X509PolicyInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509PolicyInformation)
