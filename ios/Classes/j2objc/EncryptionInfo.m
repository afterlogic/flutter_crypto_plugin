//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/EncryptionInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "EncryptionInfo.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1TspEncryptionInfo () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionInfoType_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> encryptionInfoValue_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)sequence;

- (instancetype)init;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspEncryptionInfo, encryptionInfoType_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspEncryptionInfo, encryptionInfoValue_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspEncryptionInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *sequence);

__attribute__((unused)) static LibOrgBouncycastleAsn1TspEncryptionInfo *new_LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1TspEncryptionInfo *create_LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence);

__attribute__((unused)) static void LibOrgBouncycastleAsn1TspEncryptionInfo_init(LibOrgBouncycastleAsn1TspEncryptionInfo *self);

__attribute__((unused)) static LibOrgBouncycastleAsn1TspEncryptionInfo *new_LibOrgBouncycastleAsn1TspEncryptionInfo_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1TspEncryptionInfo *create_LibOrgBouncycastleAsn1TspEncryptionInfo_init(void);

@implementation LibOrgBouncycastleAsn1TspEncryptionInfo

+ (LibOrgBouncycastleAsn1TspEncryptionInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1Object:(LibOrgBouncycastleAsn1ASN1Object *)obj {
  return LibOrgBouncycastleAsn1TspEncryptionInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1Object_(obj);
}

+ (LibOrgBouncycastleAsn1TspEncryptionInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                       withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1TspEncryptionInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)sequence {
  LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, sequence);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)encryptionInfoType
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)encryptionInfoValue {
  LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, encryptionInfoType, encryptionInfoValue);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1TspEncryptionInfo_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:encryptionInfoType_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:encryptionInfoValue_];
  return LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1TspEncryptionInfo;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1TspEncryptionInfo;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1Object:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[4].selector = @selector(init);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encryptionInfoType_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encryptionInfoValue_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1Object;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1TspEncryptionInfo = { "EncryptionInfo", "lib.org.bouncycastle.asn1.tsp", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1TspEncryptionInfo;
}

@end

LibOrgBouncycastleAsn1TspEncryptionInfo *LibOrgBouncycastleAsn1TspEncryptionInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1Object_(LibOrgBouncycastleAsn1ASN1Object *obj) {
  LibOrgBouncycastleAsn1TspEncryptionInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1TspEncryptionInfo class]]) {
    return (LibOrgBouncycastleAsn1TspEncryptionInfo *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1TspEncryptionInfo *LibOrgBouncycastleAsn1TspEncryptionInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1TspEncryptionInfo_initialize();
  return LibOrgBouncycastleAsn1TspEncryptionInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1Object_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspEncryptionInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *sequence) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(sequence)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"wrong sequence size in constructor: ", [sequence size]));
  }
  self->encryptionInfoType_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([sequence getObjectAtWithInt:0]);
  self->encryptionInfoValue_ = [sequence getObjectAtWithInt:1];
}

LibOrgBouncycastleAsn1TspEncryptionInfo *new_LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspEncryptionInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, sequence)
}

LibOrgBouncycastleAsn1TspEncryptionInfo *create_LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspEncryptionInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, sequence)
}

void LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1TspEncryptionInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionInfoType, id<LibOrgBouncycastleAsn1ASN1Encodable> encryptionInfoValue) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->encryptionInfoType_ = encryptionInfoType;
  self->encryptionInfoValue_ = encryptionInfoValue;
}

LibOrgBouncycastleAsn1TspEncryptionInfo *new_LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionInfoType, id<LibOrgBouncycastleAsn1ASN1Encodable> encryptionInfoValue) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspEncryptionInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, encryptionInfoType, encryptionInfoValue)
}

LibOrgBouncycastleAsn1TspEncryptionInfo *create_LibOrgBouncycastleAsn1TspEncryptionInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionInfoType, id<LibOrgBouncycastleAsn1ASN1Encodable> encryptionInfoValue) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspEncryptionInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, encryptionInfoType, encryptionInfoValue)
}

void LibOrgBouncycastleAsn1TspEncryptionInfo_init(LibOrgBouncycastleAsn1TspEncryptionInfo *self) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
}

LibOrgBouncycastleAsn1TspEncryptionInfo *new_LibOrgBouncycastleAsn1TspEncryptionInfo_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspEncryptionInfo, init)
}

LibOrgBouncycastleAsn1TspEncryptionInfo *create_LibOrgBouncycastleAsn1TspEncryptionInfo_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspEncryptionInfo, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1TspEncryptionInfo)
