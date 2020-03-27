//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DLSequence.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "BERTags.h"
#include "DLSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "StreamUtil.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1DLSequence () {
 @public
  jint bodyLength_;
}

- (jint)getBodyLength;

@end

__attribute__((unused)) static jint LibOrgBouncycastleAsn1DLSequence_getBodyLength(LibOrgBouncycastleAsn1DLSequence *self);

@implementation LibOrgBouncycastleAsn1DLSequence

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1DLSequence_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(self, obj);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v {
  LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(self, v);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1EncodableArray:(IOSObjectArray *)array {
  LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(self, array);
  return self;
}

- (jint)getBodyLength {
  return LibOrgBouncycastleAsn1DLSequence_getBodyLength(self);
}

- (jint)encodedLength {
  jint length = LibOrgBouncycastleAsn1DLSequence_getBodyLength(self);
  return 1 + LibOrgBouncycastleAsn1StreamUtil_calculateBodyLengthWithInt_(length) + length;
}

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg {
  LibOrgBouncycastleAsn1ASN1OutputStream *dOut = [((LibOrgBouncycastleAsn1ASN1OutputStream *) nil_chk(outArg)) getDLSubStream];
  jint length = LibOrgBouncycastleAsn1DLSequence_getBodyLength(self);
  [outArg writeWithInt:LibOrgBouncycastleAsn1BERTags_SEQUENCE | LibOrgBouncycastleAsn1BERTags_CONSTRUCTED];
  [outArg writeLengthWithInt:length];
  for (id<JavaUtilEnumeration> e = [self getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
    id obj = [e nextElement];
    [((LibOrgBouncycastleAsn1ASN1OutputStream *) nil_chk(dOut)) writeObjectWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check(obj, LibOrgBouncycastleAsn1ASN1Encodable_class_())];
  }
}

- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(__unsafe_unretained id *)stackbuf count:(NSUInteger)len {
  return JreDefaultFastEnumeration(self, state, stackbuf);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x2, -1, -1, 3, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 4, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1EncodableVector:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1EncodableArray:);
  methods[4].selector = @selector(getBodyLength);
  methods[5].selector = @selector(encodedLength);
  methods[6].selector = @selector(encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Encodable;", "LLibOrgBouncycastleAsn1ASN1EncodableVector;", "[LLibOrgBouncycastleAsn1ASN1Encodable;", "LJavaIoIOException;", "encode", "LLibOrgBouncycastleAsn1ASN1OutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DLSequence = { "DLSequence", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 7, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DLSequence;
}

@end

void LibOrgBouncycastleAsn1DLSequence_init(LibOrgBouncycastleAsn1DLSequence *self) {
  LibOrgBouncycastleAsn1ASN1Sequence_init(self);
  self->bodyLength_ = -1;
}

LibOrgBouncycastleAsn1DLSequence *new_LibOrgBouncycastleAsn1DLSequence_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DLSequence, init)
}

LibOrgBouncycastleAsn1DLSequence *create_LibOrgBouncycastleAsn1DLSequence_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DLSequence, init)
}

void LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1DLSequence *self, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(self, obj);
  self->bodyLength_ = -1;
}

LibOrgBouncycastleAsn1DLSequence *new_LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DLSequence, initWithLibOrgBouncycastleAsn1ASN1Encodable_, obj)
}

LibOrgBouncycastleAsn1DLSequence *create_LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DLSequence, initWithLibOrgBouncycastleAsn1ASN1Encodable_, obj)
}

void LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1DLSequence *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v) {
  LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(self, v);
  self->bodyLength_ = -1;
}

LibOrgBouncycastleAsn1DLSequence *new_LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DLSequence, initWithLibOrgBouncycastleAsn1ASN1EncodableVector_, v)
}

LibOrgBouncycastleAsn1DLSequence *create_LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DLSequence, initWithLibOrgBouncycastleAsn1ASN1EncodableVector_, v)
}

void LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(LibOrgBouncycastleAsn1DLSequence *self, IOSObjectArray *array) {
  LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(self, array);
  self->bodyLength_ = -1;
}

LibOrgBouncycastleAsn1DLSequence *new_LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(IOSObjectArray *array) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DLSequence, initWithLibOrgBouncycastleAsn1ASN1EncodableArray_, array)
}

LibOrgBouncycastleAsn1DLSequence *create_LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(IOSObjectArray *array) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DLSequence, initWithLibOrgBouncycastleAsn1ASN1EncodableArray_, array)
}

jint LibOrgBouncycastleAsn1DLSequence_getBodyLength(LibOrgBouncycastleAsn1DLSequence *self) {
  if (self->bodyLength_ < 0) {
    jint length = 0;
    for (id<JavaUtilEnumeration> e = [self getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
      id obj = [e nextElement];
      length += [((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check(obj, LibOrgBouncycastleAsn1ASN1Encodable_class_())))) toASN1Primitive])) toDLObject])) encodedLength];
    }
    self->bodyLength_ = length;
  }
  return self->bodyLength_;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DLSequence)
