//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/SignedDataParser.java
//

#include "ASN1Encodable.h"
#include "ASN1Integer.h"
#include "ASN1Sequence.h"
#include "ASN1SequenceParser.h"
#include "ASN1Set.h"
#include "ASN1SetParser.h"
#include "ASN1TaggedObjectParser.h"
#include "BERTags.h"
#include "ContentInfoParser.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "SignedDataParser.h"
#include "java/io/IOException.h"

@interface LibOrgBouncycastleAsn1CmsSignedDataParser () {
 @public
  id<LibOrgBouncycastleAsn1ASN1SequenceParser> _seq_;
  LibOrgBouncycastleAsn1ASN1Integer *_version_;
  id _nextObject_;
  jboolean _certsCalled_;
  jboolean _crlsCalled_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1SequenceParser:(id<LibOrgBouncycastleAsn1ASN1SequenceParser>)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsSignedDataParser, _seq_, id<LibOrgBouncycastleAsn1ASN1SequenceParser>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsSignedDataParser, _version_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsSignedDataParser, _nextObject_, id)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(LibOrgBouncycastleAsn1CmsSignedDataParser *self, id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsSignedDataParser *new_LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsSignedDataParser *create_LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq);

@implementation LibOrgBouncycastleAsn1CmsSignedDataParser

+ (LibOrgBouncycastleAsn1CmsSignedDataParser *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmsSignedDataParser_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1SequenceParser:(id<LibOrgBouncycastleAsn1ASN1SequenceParser>)seq {
  LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(self, seq);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return _version_;
}

- (id<LibOrgBouncycastleAsn1ASN1SetParser>)getDigestAlgorithms {
  id o = [((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) nil_chk(_seq_)) readObject];
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Set class]]) {
    return [((LibOrgBouncycastleAsn1ASN1Set *) nil_chk(((LibOrgBouncycastleAsn1ASN1Set *) o))) parser];
  }
  return (id<LibOrgBouncycastleAsn1ASN1SetParser>) cast_check(o, LibOrgBouncycastleAsn1ASN1SetParser_class_());
}

- (LibOrgBouncycastleAsn1CmsContentInfoParser *)getEncapContentInfo {
  return new_LibOrgBouncycastleAsn1CmsContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) cast_check([((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) nil_chk(_seq_)) readObject], LibOrgBouncycastleAsn1ASN1SequenceParser_class_()));
}

- (id<LibOrgBouncycastleAsn1ASN1SetParser>)getCertificates {
  _certsCalled_ = true;
  _nextObject_ = [((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) nil_chk(_seq_)) readObject];
  if ([LibOrgBouncycastleAsn1ASN1TaggedObjectParser_class_() isInstance:_nextObject_] && [((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) cast_check(_nextObject_, LibOrgBouncycastleAsn1ASN1TaggedObjectParser_class_())))) getTagNo] == 0) {
    id<LibOrgBouncycastleAsn1ASN1SetParser> certs = (id<LibOrgBouncycastleAsn1ASN1SetParser>) cast_check([((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) cast_check(_nextObject_, LibOrgBouncycastleAsn1ASN1TaggedObjectParser_class_())))) getObjectParserWithInt:LibOrgBouncycastleAsn1BERTags_SET withBoolean:false], LibOrgBouncycastleAsn1ASN1SetParser_class_());
    _nextObject_ = nil;
    return certs;
  }
  return nil;
}

- (id<LibOrgBouncycastleAsn1ASN1SetParser>)getCrls {
  if (!_certsCalled_) {
    @throw new_JavaIoIOException_initWithNSString_(@"getCerts() has not been called.");
  }
  _crlsCalled_ = true;
  if (_nextObject_ == nil) {
    _nextObject_ = [((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) nil_chk(_seq_)) readObject];
  }
  if ([LibOrgBouncycastleAsn1ASN1TaggedObjectParser_class_() isInstance:_nextObject_] && [((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) cast_check(_nextObject_, LibOrgBouncycastleAsn1ASN1TaggedObjectParser_class_())))) getTagNo] == 1) {
    id<LibOrgBouncycastleAsn1ASN1SetParser> crls = (id<LibOrgBouncycastleAsn1ASN1SetParser>) cast_check([((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) cast_check(_nextObject_, LibOrgBouncycastleAsn1ASN1TaggedObjectParser_class_())))) getObjectParserWithInt:LibOrgBouncycastleAsn1BERTags_SET withBoolean:false], LibOrgBouncycastleAsn1ASN1SetParser_class_());
    _nextObject_ = nil;
    return crls;
  }
  return nil;
}

- (id<LibOrgBouncycastleAsn1ASN1SetParser>)getSignerInfos {
  if (!_certsCalled_ || !_crlsCalled_) {
    @throw new_JavaIoIOException_initWithNSString_(@"getCerts() and/or getCrls() has not been called.");
  }
  if (_nextObject_ == nil) {
    _nextObject_ = [((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) nil_chk(_seq_)) readObject];
  }
  return (id<LibOrgBouncycastleAsn1ASN1SetParser>) cast_check(_nextObject_, LibOrgBouncycastleAsn1ASN1SetParser_class_());
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmsSignedDataParser;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1SetParser;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsContentInfoParser;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1SetParser;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1SetParser;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1SetParser;", 0x1, -1, -1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1SequenceParser:);
  methods[2].selector = @selector(getVersion);
  methods[3].selector = @selector(getDigestAlgorithms);
  methods[4].selector = @selector(getEncapContentInfo);
  methods[5].selector = @selector(getCertificates);
  methods[6].selector = @selector(getCrls);
  methods[7].selector = @selector(getSignerInfos);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_seq_", "LLibOrgBouncycastleAsn1ASN1SequenceParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_version_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_nextObject_", "LNSObject;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_certsCalled_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_crlsCalled_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LJavaIoIOException;", "LLibOrgBouncycastleAsn1ASN1SequenceParser;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsSignedDataParser = { "SignedDataParser", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 8, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsSignedDataParser;
}

@end

LibOrgBouncycastleAsn1CmsSignedDataParser *LibOrgBouncycastleAsn1CmsSignedDataParser_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmsSignedDataParser_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(((LibOrgBouncycastleAsn1ASN1Sequence *) o))) parser]);
  }
  if ([LibOrgBouncycastleAsn1ASN1SequenceParser_class_() isInstance:o]) {
    return new_LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) cast_check(o, LibOrgBouncycastleAsn1ASN1SequenceParser_class_()));
  }
  @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"unknown object encountered: ", [[nil_chk(o) java_getClass] getName]));
}

void LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(LibOrgBouncycastleAsn1CmsSignedDataParser *self, id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) {
  NSObject_init(self);
  self->_seq_ = seq;
  self->_version_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) nil_chk(seq)) readObject], [LibOrgBouncycastleAsn1ASN1Integer class]);
}

LibOrgBouncycastleAsn1CmsSignedDataParser *new_LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsSignedDataParser, initWithLibOrgBouncycastleAsn1ASN1SequenceParser_, seq)
}

LibOrgBouncycastleAsn1CmsSignedDataParser *create_LibOrgBouncycastleAsn1CmsSignedDataParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsSignedDataParser, initWithLibOrgBouncycastleAsn1ASN1SequenceParser_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsSignedDataParser)
