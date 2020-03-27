//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/x509/JcajceX509PEMUtil.java
//

#include "ASN1Sequence.h"
#include "Base64.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceX509PEMUtil.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "java/lang/Exception.h"
#include "java/lang/StringBuffer.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil () {
 @public
  NSString *_header1_;
  NSString *_header2_;
  NSString *_header3_;
  NSString *_footer1_;
  NSString *_footer2_;
  NSString *_footer3_;
}

- (NSString *)readLineWithJavaIoInputStream:(JavaIoInputStream *)inArg;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, _header1_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, _header2_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, _header3_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, _footer1_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, _footer2_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, _footer3_, NSString *)

__attribute__((unused)) static NSString *LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_readLineWithJavaIoInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *self, JavaIoInputStream *inArg);

@implementation LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil

- (instancetype)initWithNSString:(NSString *)type {
  LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_initWithNSString_(self, type);
  return self;
}

- (NSString *)readLineWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_readLineWithJavaIoInputStream_(self, inArg);
}

- (LibOrgBouncycastleAsn1ASN1Sequence *)readPEMObjectWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  NSString *line;
  JavaLangStringBuffer *pemBuf = new_JavaLangStringBuffer_init();
  while ((line = LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_readLineWithJavaIoInputStream_(self, inArg)) != nil) {
    if ([((NSString *) nil_chk(line)) java_hasPrefix:_header1_] || [line java_hasPrefix:_header2_] || [line java_hasPrefix:_header3_]) {
      break;
    }
  }
  while ((line = LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_readLineWithJavaIoInputStream_(self, inArg)) != nil) {
    if ([((NSString *) nil_chk(line)) java_hasPrefix:_footer1_] || [line java_hasPrefix:_footer2_] || [line java_hasPrefix:_footer3_]) {
      break;
    }
    (void) [pemBuf appendWithNSString:line];
  }
  if ([pemBuf java_length] != 0) {
    @try {
      return LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(LibOrgBouncycastleUtilEncodersBase64_decodeWithNSString_([pemBuf description]));
    }
    @catch (JavaLangException *e) {
      @throw new_JavaIoIOException_initWithNSString_(@"malformed PEM data encountered");
    }
  }
  return nil;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x2, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0x0, 4, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(readLineWithJavaIoInputStream:);
  methods[2].selector = @selector(readPEMObjectWithJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_header1_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_header2_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_header3_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_footer1_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_footer2_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_footer3_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "readLine", "LJavaIoInputStream;", "LJavaIoIOException;", "readPEMObject" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil = { "JcajceX509PEMUtil", "lib.org.bouncycastle.jcajce.provider.asymmetric.x509", ptrTable, methods, fields, 7, 0x0, 3, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_initWithNSString_(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *self, NSString *type) {
  NSObject_init(self);
  self->_header1_ = JreStrcat("$$$", @"-----BEGIN ", type, @"-----");
  self->_header2_ = JreStrcat("$$$", @"-----BEGIN X509 ", type, @"-----");
  self->_header3_ = @"-----BEGIN PKCS7-----";
  self->_footer1_ = JreStrcat("$$$", @"-----END ", type, @"-----");
  self->_footer2_ = JreStrcat("$$$", @"-----END X509 ", type, @"-----");
  self->_footer3_ = @"-----END PKCS7-----";
}

LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_initWithNSString_(NSString *type) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, initWithNSString_, type)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *create_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_initWithNSString_(NSString *type) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil, initWithNSString_, type)
}

NSString *LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_readLineWithJavaIoInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *self, JavaIoInputStream *inArg) {
  jint c;
  JavaLangStringBuffer *l = new_JavaLangStringBuffer_init();
  do {
    while (((c = [((JavaIoInputStream *) nil_chk(inArg)) read]) != 0x000d) && c != 0x000a && (c >= 0)) {
      (void) [l appendWithChar:(jchar) c];
    }
  }
  while (c >= 0 && [l java_length] == 0);
  if (c < 0) {
    return nil;
  }
  if (c == 0x000d) {
    [inArg markWithInt:1];
    if ((c = [inArg read]) == 0x000a) {
      [inArg markWithInt:1];
    }
    if (c > 0) {
      [inArg reset];
    }
  }
  return [l description];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil)
