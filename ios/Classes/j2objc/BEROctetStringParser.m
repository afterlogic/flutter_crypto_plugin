//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/BEROctetStringParser.java
//

#include "ASN1ParsingException.h"
#include "ASN1Primitive.h"
#include "ASN1StreamParser.h"
#include "BEROctetString.h"
#include "BEROctetStringParser.h"
#include "ConstructedOctetStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Streams.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"

@interface LibOrgBouncycastleAsn1BEROctetStringParser () {
 @public
  LibOrgBouncycastleAsn1ASN1StreamParser *_parser_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1BEROctetStringParser, _parser_, LibOrgBouncycastleAsn1ASN1StreamParser *)

@implementation LibOrgBouncycastleAsn1BEROctetStringParser

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1StreamParser:(LibOrgBouncycastleAsn1ASN1StreamParser *)parser {
  LibOrgBouncycastleAsn1BEROctetStringParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(self, parser);
  return self;
}

- (JavaIoInputStream *)getOctetStream {
  return new_LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(_parser_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject {
  return new_LibOrgBouncycastleAsn1BEROctetString_initWithByteArray_(LibOrgBouncycastleUtilIoStreams_readAllWithJavaIoInputStream_([self getOctetStream]));
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  @try {
    return [self getLoadedObject];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"IOException converting stream to byte array: ", [e getMessage]), e);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaIoInputStream;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1StreamParser:);
  methods[1].selector = @selector(getOctetStream);
  methods[2].selector = @selector(getLoadedObject);
  methods[3].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_parser_", "LLibOrgBouncycastleAsn1ASN1StreamParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1StreamParser;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1BEROctetStringParser = { "BEROctetStringParser", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1BEROctetStringParser;
}

@end

void LibOrgBouncycastleAsn1BEROctetStringParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1BEROctetStringParser *self, LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  NSObject_init(self);
  self->_parser_ = parser;
}

LibOrgBouncycastleAsn1BEROctetStringParser *new_LibOrgBouncycastleAsn1BEROctetStringParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1BEROctetStringParser, initWithLibOrgBouncycastleAsn1ASN1StreamParser_, parser)
}

LibOrgBouncycastleAsn1BEROctetStringParser *create_LibOrgBouncycastleAsn1BEROctetStringParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1BEROctetStringParser, initWithLibOrgBouncycastleAsn1ASN1StreamParser_, parser)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1BEROctetStringParser)
