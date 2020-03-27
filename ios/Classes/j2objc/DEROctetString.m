//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DEROctetString.java
//

#include "ASN1Encodable.h"
#include "ASN1Encoding.h"
#include "ASN1OctetString.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "BERTags.h"
#include "DEROctetString.h"
#include "DEROutputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "StreamUtil.h"

@implementation LibOrgBouncycastleAsn1DEROctetString

- (instancetype)initWithByteArray:(IOSByteArray *)string {
  LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(self, string);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1DEROctetString_initWithLibOrgBouncycastleAsn1ASN1Encodable_(self, obj);
  return self;
}

- (jboolean)isConstructed {
  return false;
}

- (jint)encodedLength {
  return 1 + LibOrgBouncycastleAsn1StreamUtil_calculateBodyLengthWithInt_(((IOSByteArray *) nil_chk(string_))->size_) + ((IOSByteArray *) nil_chk(string_))->size_;
}

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg {
  [((LibOrgBouncycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:LibOrgBouncycastleAsn1BERTags_OCTET_STRING withByteArray:string_];
}

+ (void)encodeWithLibOrgBouncycastleAsn1DEROutputStream:(LibOrgBouncycastleAsn1DEROutputStream *)derOut
                                          withByteArray:(IOSByteArray *)bytes {
  LibOrgBouncycastleAsn1DEROctetString_encodeWithLibOrgBouncycastleAsn1DEROutputStream_withByteArray_(derOut, bytes);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 3, 4, 2, -1, -1, -1 },
    { NULL, "V", 0x8, 3, 5, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[2].selector = @selector(isConstructed);
  methods[3].selector = @selector(encodedLength);
  methods[4].selector = @selector(encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:);
  methods[5].selector = @selector(encodeWithLibOrgBouncycastleAsn1DEROutputStream:withByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "[B", "LLibOrgBouncycastleAsn1ASN1Encodable;", "LJavaIoIOException;", "encode", "LLibOrgBouncycastleAsn1ASN1OutputStream;", "LLibOrgBouncycastleAsn1DEROutputStream;[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DEROctetString = { "DEROctetString", "lib.org.bouncycastle.asn1", ptrTable, methods, NULL, 7, 0x1, 6, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DEROctetString;
}

@end

void LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(LibOrgBouncycastleAsn1DEROctetString *self, IOSByteArray *string) {
  LibOrgBouncycastleAsn1ASN1OctetString_initWithByteArray_(self, string);
}

LibOrgBouncycastleAsn1DEROctetString *new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DEROctetString, initWithByteArray_, string)
}

LibOrgBouncycastleAsn1DEROctetString *create_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DEROctetString, initWithByteArray_, string)
}

void LibOrgBouncycastleAsn1DEROctetString_initWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1DEROctetString *self, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  LibOrgBouncycastleAsn1ASN1OctetString_initWithByteArray_(self, [((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(obj)) toASN1Primitive])) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER]);
}

LibOrgBouncycastleAsn1DEROctetString *new_LibOrgBouncycastleAsn1DEROctetString_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DEROctetString, initWithLibOrgBouncycastleAsn1ASN1Encodable_, obj)
}

LibOrgBouncycastleAsn1DEROctetString *create_LibOrgBouncycastleAsn1DEROctetString_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DEROctetString, initWithLibOrgBouncycastleAsn1ASN1Encodable_, obj)
}

void LibOrgBouncycastleAsn1DEROctetString_encodeWithLibOrgBouncycastleAsn1DEROutputStream_withByteArray_(LibOrgBouncycastleAsn1DEROutputStream *derOut, IOSByteArray *bytes) {
  LibOrgBouncycastleAsn1DEROctetString_initialize();
  [((LibOrgBouncycastleAsn1DEROutputStream *) nil_chk(derOut)) writeEncodedWithInt:LibOrgBouncycastleAsn1BERTags_OCTET_STRING withByteArray:bytes];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DEROctetString)
