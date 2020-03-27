//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/TimeStampTokenEvidence.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "TimeStampAndCRL.h"
#include "TimeStampTokenEvidence.h"
#include "java/lang/System.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence () {
 @public
  IOSObjectArray *timeStampAndCRLs_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (IOSObjectArray *)copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray:(IOSObjectArray *)tsAndCrls OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence, timeStampAndCRLs_, IOSObjectArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *new_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *create_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, IOSObjectArray *tsAndCrls);

@implementation LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence

- (instancetype)initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray:(IOSObjectArray *)timeStampAndCRLs {
  LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(self, timeStampAndCRLs);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL:(LibOrgBouncycastleAsn1CmsTimeStampAndCRL *)timeStampAndCRL {
  LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_(self, timeStampAndCRL);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)tagged
                                                                                               withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, explicit_);
}

+ (LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithId_(obj);
}

- (IOSObjectArray *)toTimeStampAndCRLArray {
  return LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(self, timeStampAndCRLs_);
}

- (IOSObjectArray *)copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray:(IOSObjectArray *)tsAndCrls {
  return LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(self, tsAndCrls);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(timeStampAndCRLs_))->size_; i++) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(timeStampAndCRLs_, i)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsTimeStampTokenEvidence;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsTimeStampTokenEvidence;", 0x9, 3, 5, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CmsTimeStampAndCRL;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CmsTimeStampAndCRL;", 0x2, 6, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(toTimeStampAndCRLArray);
  methods[6].selector = @selector(copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray:);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "timeStampAndCRLs_", "[LLibOrgBouncycastleAsn1CmsTimeStampAndCRL;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[LLibOrgBouncycastleAsn1CmsTimeStampAndCRL;", "LLibOrgBouncycastleAsn1CmsTimeStampAndCRL;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "copy" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence = { "TimeStampTokenEvidence", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 8, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence;
}

@end

void LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, IOSObjectArray *timeStampAndCRLs) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->timeStampAndCRLs_ = LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(self, timeStampAndCRLs);
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *new_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(IOSObjectArray *timeStampAndCRLs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence, initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_, timeStampAndCRLs)
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *create_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(IOSObjectArray *timeStampAndCRLs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence, initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_, timeStampAndCRLs)
}

void LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, LibOrgBouncycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->timeStampAndCRLs_ = [IOSObjectArray newArrayWithLength:1 type:LibOrgBouncycastleAsn1CmsTimeStampAndCRL_class_()];
  (void) IOSObjectArray_Set(self->timeStampAndCRLs_, 0, timeStampAndCRL);
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *new_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_(LibOrgBouncycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence, initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_, timeStampAndCRL)
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *create_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_(LibOrgBouncycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence, initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_, timeStampAndCRL)
}

void LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->timeStampAndCRLs_ = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] type:LibOrgBouncycastleAsn1CmsTimeStampAndCRL_class_()];
  jint count = 0;
  for (id<JavaUtilEnumeration> en = [seq getObjects]; [((id<JavaUtilEnumeration>) nil_chk(en)) hasMoreElements]; ) {
    (void) IOSObjectArray_Set(nil_chk(self->timeStampAndCRLs_), count++, LibOrgBouncycastleAsn1CmsTimeStampAndCRL_getInstanceWithId_([en nextElement]));
  }
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *new_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *create_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *tagged, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initialize();
  return LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, explicit_));
}

LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence class]]) {
    return (LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

IOSObjectArray *LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_copy__WithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, IOSObjectArray *tsAndCrls) {
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(tsAndCrls))->size_ type:LibOrgBouncycastleAsn1CmsTimeStampAndCRL_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(tsAndCrls, 0, tmp, 0, tmp->size_);
  return tmp;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence)