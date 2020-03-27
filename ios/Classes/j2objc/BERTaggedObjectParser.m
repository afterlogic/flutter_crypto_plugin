//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/BERTaggedObjectParser.java
//

#include "ASN1Encodable.h"
#include "ASN1ParsingException.h"
#include "ASN1Primitive.h"
#include "ASN1StreamParser.h"
#include "BERTaggedObjectParser.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"

@interface LibOrgBouncycastleAsn1BERTaggedObjectParser () {
 @public
  jboolean _constructed_;
  jint _tagNumber_;
  LibOrgBouncycastleAsn1ASN1StreamParser *_parser_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1BERTaggedObjectParser, _parser_, LibOrgBouncycastleAsn1ASN1StreamParser *)

@implementation LibOrgBouncycastleAsn1BERTaggedObjectParser

- (instancetype)initWithBoolean:(jboolean)constructed
                        withInt:(jint)tagNumber
withLibOrgBouncycastleAsn1ASN1StreamParser:(LibOrgBouncycastleAsn1ASN1StreamParser *)parser {
  LibOrgBouncycastleAsn1BERTaggedObjectParser_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1StreamParser_(self, constructed, tagNumber, parser);
  return self;
}

- (jboolean)isConstructed {
  return _constructed_;
}

- (jint)getTagNo {
  return _tagNumber_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getObjectParserWithInt:(jint)tag
                                                      withBoolean:(jboolean)isExplicit {
  if (isExplicit) {
    if (!_constructed_) {
      @throw new_JavaIoIOException_initWithNSString_(@"Explicit tags must be constructed (see X.690 8.14.2)");
    }
    return [((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readObject];
  }
  return [((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readImplicitWithBoolean:_constructed_ withInt:tag];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject {
  return [((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readTaggedObjectWithBoolean:_constructed_ withInt:_tagNumber_];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  @try {
    return [self getLoadedObject];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_([e getMessage]);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withInt:withLibOrgBouncycastleAsn1ASN1StreamParser:);
  methods[1].selector = @selector(isConstructed);
  methods[2].selector = @selector(getTagNo);
  methods[3].selector = @selector(getObjectParserWithInt:withBoolean:);
  methods[4].selector = @selector(getLoadedObject);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_constructed_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_tagNumber_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_parser_", "LLibOrgBouncycastleAsn1ASN1StreamParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZILLibOrgBouncycastleAsn1ASN1StreamParser;", "getObjectParser", "IZ", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1BERTaggedObjectParser = { "BERTaggedObjectParser", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1BERTaggedObjectParser;
}

@end

void LibOrgBouncycastleAsn1BERTaggedObjectParser_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1BERTaggedObjectParser *self, jboolean constructed, jint tagNumber, LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  NSObject_init(self);
  self->_constructed_ = constructed;
  self->_tagNumber_ = tagNumber;
  self->_parser_ = parser;
}

LibOrgBouncycastleAsn1BERTaggedObjectParser *new_LibOrgBouncycastleAsn1BERTaggedObjectParser_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1StreamParser_(jboolean constructed, jint tagNumber, LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1BERTaggedObjectParser, initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1StreamParser_, constructed, tagNumber, parser)
}

LibOrgBouncycastleAsn1BERTaggedObjectParser *create_LibOrgBouncycastleAsn1BERTaggedObjectParser_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1StreamParser_(jboolean constructed, jint tagNumber, LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1BERTaggedObjectParser, initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1StreamParser_, constructed, tagNumber, parser)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1BERTaggedObjectParser)
