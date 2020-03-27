//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DERUTF8String.java
//

#include "ASN1OctetString.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "Arrays.h"
#include "BERTags.h"
#include "DERUTF8String.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "StreamUtil.h"
#include "Strings.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1DERUTF8String () {
 @public
  IOSByteArray *string_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DERUTF8String, string_, IOSByteArray *)

@implementation LibOrgBouncycastleAsn1DERUTF8String

+ (LibOrgBouncycastleAsn1DERUTF8String *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1DERUTF8String *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                   withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithByteArray:(IOSByteArray *)string {
  LibOrgBouncycastleAsn1DERUTF8String_initWithByteArray_(self, string);
  return self;
}

- (instancetype)initWithNSString:(NSString *)string {
  LibOrgBouncycastleAsn1DERUTF8String_initWithNSString_(self, string);
  return self;
}

- (NSString *)getString {
  return LibOrgBouncycastleUtilStrings_fromUTF8ByteArrayWithByteArray_(string_);
}

- (NSString *)description {
  return [self getString];
}

- (NSUInteger)hash {
  return LibOrgBouncycastleUtilArrays_hashCodeWithByteArray_(string_);
}

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[LibOrgBouncycastleAsn1DERUTF8String class]])) {
    return false;
  }
  LibOrgBouncycastleAsn1DERUTF8String *s = (LibOrgBouncycastleAsn1DERUTF8String *) cast_chk(o, [LibOrgBouncycastleAsn1DERUTF8String class]);
  return LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(string_, ((LibOrgBouncycastleAsn1DERUTF8String *) nil_chk(s))->string_);
}

- (jboolean)isConstructed {
  return false;
}

- (jint)encodedLength {
  return 1 + LibOrgBouncycastleAsn1StreamUtil_calculateBodyLengthWithInt_(((IOSByteArray *) nil_chk(string_))->size_) + string_->size_;
}

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg {
  [((LibOrgBouncycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:LibOrgBouncycastleAsn1BERTags_UTF8_STRING withByteArray:string_];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1DERUTF8String;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERUTF8String;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, 7, 8, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, 9, -1, -1, -1 },
    { NULL, "V", 0x0, 10, 11, 9, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(initWithNSString:);
  methods[4].selector = @selector(getString);
  methods[5].selector = @selector(description);
  methods[6].selector = @selector(hash);
  methods[7].selector = @selector(asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[8].selector = @selector(isConstructed);
  methods[9].selector = @selector(encodedLength);
  methods[10].selector = @selector(encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "string_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "[B", "LNSString;", "toString", "hashCode", "asn1Equals", "LLibOrgBouncycastleAsn1ASN1Primitive;", "LJavaIoIOException;", "encode", "LLibOrgBouncycastleAsn1ASN1OutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DERUTF8String = { "DERUTF8String", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 11, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DERUTF8String;
}

@end

LibOrgBouncycastleAsn1DERUTF8String *LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1DERUTF8String_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1DERUTF8String class]]) {
    return (LibOrgBouncycastleAsn1DERUTF8String *) cast_chk(obj, [LibOrgBouncycastleAsn1DERUTF8String class]);
  }
  if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return (LibOrgBouncycastleAsn1DERUTF8String *) cast_chk(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])), [LibOrgBouncycastleAsn1DERUTF8String class]);
    }
    @catch (JavaLangException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"encoding error in getInstance: ", [e description]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

LibOrgBouncycastleAsn1DERUTF8String *LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1DERUTF8String_initialize();
  LibOrgBouncycastleAsn1ASN1Primitive *o = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject];
  if (explicit_ || [o isKindOfClass:[LibOrgBouncycastleAsn1DERUTF8String class]]) {
    return LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithId_(o);
  }
  else {
    return new_LibOrgBouncycastleAsn1DERUTF8String_initWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_(o))) getOctets]);
  }
}

void LibOrgBouncycastleAsn1DERUTF8String_initWithByteArray_(LibOrgBouncycastleAsn1DERUTF8String *self, IOSByteArray *string) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->string_ = string;
}

LibOrgBouncycastleAsn1DERUTF8String *new_LibOrgBouncycastleAsn1DERUTF8String_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DERUTF8String, initWithByteArray_, string)
}

LibOrgBouncycastleAsn1DERUTF8String *create_LibOrgBouncycastleAsn1DERUTF8String_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DERUTF8String, initWithByteArray_, string)
}

void LibOrgBouncycastleAsn1DERUTF8String_initWithNSString_(LibOrgBouncycastleAsn1DERUTF8String *self, NSString *string) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->string_ = LibOrgBouncycastleUtilStrings_toUTF8ByteArrayWithNSString_(string);
}

LibOrgBouncycastleAsn1DERUTF8String *new_LibOrgBouncycastleAsn1DERUTF8String_initWithNSString_(NSString *string) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DERUTF8String, initWithNSString_, string)
}

LibOrgBouncycastleAsn1DERUTF8String *create_LibOrgBouncycastleAsn1DERUTF8String_initWithNSString_(NSString *string) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DERUTF8String, initWithNSString_, string)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DERUTF8String)
