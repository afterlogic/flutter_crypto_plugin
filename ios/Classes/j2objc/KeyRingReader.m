//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/parsing/KeyRingReader.java
//

#include "BcKeyFingerprintCalculator.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyRingReader.h"
#include "PGPKeyRingUtil.h"
#include "PGPPublicKeyRing.h"
#include "PGPPublicKeyRingCollection.h"
#include "PGPSecretKeyRing.h"
#include "PGPSecretKeyRingCollection.h"
#include "PGPUtil.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/lang/NullPointerException.h"
#include "java/nio/charset/Charset.h"

J2OBJC_INITIALIZED_DEFN(LibComAfterlogicPgpKeyParsingKeyRingReader)

JavaNioCharsetCharset *LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8;

@implementation LibComAfterlogicPgpKeyParsingKeyRingReader

+ (JavaNioCharsetCharset *)UTF8 {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeyParsingKeyRingReader_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingWithJavaIoInputStream_(inputStream);
}

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingWithByteArray:(IOSByteArray *)bytes {
  return [self publicKeyRingWithJavaIoInputStream:new_JavaIoByteArrayInputStream_initWithByteArray_(bytes)];
}

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingWithNSString:(NSString *)asciiArmored {
  return [self publicKeyRingWithByteArray:[((NSString *) nil_chk(asciiArmored)) java_getBytesWithCharset:LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8]];
}

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingCollectionWithJavaIoInputStream_(inputStream);
}

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRingCollectionWithByteArray:(IOSByteArray *)bytes {
  return [self publicKeyRingCollectionWithJavaIoInputStream:new_JavaIoByteArrayInputStream_initWithByteArray_(bytes)];
}

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRingCollectionWithNSString:(NSString *)asciiArmored {
  return [self publicKeyRingCollectionWithByteArray:[((NSString *) nil_chk(asciiArmored)) java_getBytesWithCharset:LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8]];
}

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingWithJavaIoInputStream_(inputStream);
}

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRingWithByteArray:(IOSByteArray *)bytes {
  return [self secretKeyRingWithJavaIoInputStream:new_JavaIoByteArrayInputStream_initWithByteArray_(bytes)];
}

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRingWithNSString:(NSString *)asciiArmored {
  return [self secretKeyRingWithByteArray:[((NSString *) nil_chk(asciiArmored)) java_getBytesWithCharset:LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8]];
}

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingCollectionWithJavaIoInputStream_(inputStream);
}

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRingCollectionWithByteArray:(IOSByteArray *)bytes {
  return [self secretKeyRingCollectionWithJavaIoInputStream:new_JavaIoByteArrayInputStream_initWithByteArray_(bytes)];
}

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRingCollectionWithNSString:(NSString *)asciiArmored {
  return [self secretKeyRingCollectionWithByteArray:[((NSString *) nil_chk(asciiArmored)) java_getBytesWithCharset:LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8]];
}

- (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)keyRingWithJavaIoInputStream:(JavaIoInputStream *)publicIn
                                                           withJavaIoInputStream:(JavaIoInputStream *)secretIn {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readKeyRingWithJavaIoInputStream_withJavaIoInputStream_(publicIn, secretIn);
}

- (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)keyRingWithByteArray:(IOSByteArray *)publicBytes
                                                           withByteArray:(IOSByteArray *)secretBytes {
  return [self keyRingWithJavaIoInputStream:publicBytes != nil ? new_JavaIoByteArrayInputStream_initWithByteArray_(publicBytes) : nil withJavaIoInputStream:secretBytes != nil ? new_JavaIoByteArrayInputStream_initWithByteArray_(secretBytes) : nil];
}

- (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)keyRingWithNSString:(NSString *)asciiPublic
                                                           withNSString:(NSString *)asciiSecret {
  return [self keyRingWithByteArray:asciiPublic != nil ? [asciiPublic java_getBytesWithCharset:LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8] : nil withByteArray:asciiSecret != nil ? [asciiSecret java_getBytesWithCharset:LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8] : nil];
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)readPublicKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingWithJavaIoInputStream_(inputStream);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)readPublicKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingCollectionWithJavaIoInputStream_(inputStream);
}

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)readSecretKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingWithJavaIoInputStream_(inputStream);
}

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)readSecretKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingCollectionWithJavaIoInputStream_(inputStream);
}

+ (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)readKeyRingWithJavaIoInputStream:(JavaIoInputStream *)publicIn
                                                               withJavaIoInputStream:(JavaIoInputStream *)secretIn {
  return LibComAfterlogicPgpKeyParsingKeyRingReader_readKeyRingWithJavaIoInputStream_withJavaIoInputStream_(publicIn, secretIn);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x1, 0, 3, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x1, 0, 4, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", 0x1, 5, 1, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", 0x1, 5, 3, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", 0x1, 5, 4, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", 0x1, 7, 1, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", 0x1, 7, 3, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", 0x1, 7, 4, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", 0x1, 8, 1, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", 0x1, 8, 3, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", 0x1, 8, 4, 6, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyCollectionPGPKeyRingUtil;", 0x1, 9, 10, 6, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyCollectionPGPKeyRingUtil;", 0x1, 9, 11, 6, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyCollectionPGPKeyRingUtil;", 0x1, 9, 12, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x9, 13, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", 0x9, 14, 1, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", 0x9, 15, 1, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", 0x9, 16, 1, 6, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyCollectionPGPKeyRingUtil;", 0x9, 17, 10, 6, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(publicKeyRingWithJavaIoInputStream:);
  methods[2].selector = @selector(publicKeyRingWithByteArray:);
  methods[3].selector = @selector(publicKeyRingWithNSString:);
  methods[4].selector = @selector(publicKeyRingCollectionWithJavaIoInputStream:);
  methods[5].selector = @selector(publicKeyRingCollectionWithByteArray:);
  methods[6].selector = @selector(publicKeyRingCollectionWithNSString:);
  methods[7].selector = @selector(secretKeyRingWithJavaIoInputStream:);
  methods[8].selector = @selector(secretKeyRingWithByteArray:);
  methods[9].selector = @selector(secretKeyRingWithNSString:);
  methods[10].selector = @selector(secretKeyRingCollectionWithJavaIoInputStream:);
  methods[11].selector = @selector(secretKeyRingCollectionWithByteArray:);
  methods[12].selector = @selector(secretKeyRingCollectionWithNSString:);
  methods[13].selector = @selector(keyRingWithJavaIoInputStream:withJavaIoInputStream:);
  methods[14].selector = @selector(keyRingWithByteArray:withByteArray:);
  methods[15].selector = @selector(keyRingWithNSString:withNSString:);
  methods[16].selector = @selector(readPublicKeyRingWithJavaIoInputStream:);
  methods[17].selector = @selector(readPublicKeyRingCollectionWithJavaIoInputStream:);
  methods[18].selector = @selector(readSecretKeyRingWithJavaIoInputStream:);
  methods[19].selector = @selector(readSecretKeyRingCollectionWithJavaIoInputStream:);
  methods[20].selector = @selector(readKeyRingWithJavaIoInputStream:withJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "UTF8", "LJavaNioCharsetCharset;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
  };
  static const void *ptrTable[] = { "publicKeyRing", "LJavaIoInputStream;", "LJavaIoIOException;", "[B", "LNSString;", "publicKeyRingCollection", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "secretKeyRing", "secretKeyRingCollection", "keyRing", "LJavaIoInputStream;LJavaIoInputStream;", "[B[B", "LNSString;LNSString;", "readPublicKeyRing", "readPublicKeyRingCollection", "readSecretKeyRing", "readSecretKeyRingCollection", "readKeyRing", &LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8 };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyParsingKeyRingReader = { "KeyRingReader", "lib.com.afterlogic.pgp.key.parsing", ptrTable, methods, fields, 7, 0x1, 21, 1, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyParsingKeyRingReader;
}

+ (void)initialize {
  if (self == [LibComAfterlogicPgpKeyParsingKeyRingReader class]) {
    LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8 = JavaNioCharsetCharset_forNameWithNSString_(@"UTF-8");
    J2OBJC_SET_INITIALIZED(LibComAfterlogicPgpKeyParsingKeyRingReader)
  }
}

@end

void LibComAfterlogicPgpKeyParsingKeyRingReader_init(LibComAfterlogicPgpKeyParsingKeyRingReader *self) {
  NSObject_init(self);
}

LibComAfterlogicPgpKeyParsingKeyRingReader *new_LibComAfterlogicPgpKeyParsingKeyRingReader_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyParsingKeyRingReader, init)
}

LibComAfterlogicPgpKeyParsingKeyRingReader *create_LibComAfterlogicPgpKeyParsingKeyRingReader_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyParsingKeyRingReader, init)
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingWithJavaIoInputStream_(JavaIoInputStream *inputStream) {
  LibComAfterlogicPgpKeyParsingKeyRingReader_initialize();
  return new_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(inputStream), new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init());
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingCollectionWithJavaIoInputStream_(JavaIoInputStream *inputStream) {
  LibComAfterlogicPgpKeyParsingKeyRingReader_initialize();
  return new_LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(inputStream), new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init());
}

LibOrgBouncycastleOpenpgpPGPSecretKeyRing *LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingWithJavaIoInputStream_(JavaIoInputStream *inputStream) {
  LibComAfterlogicPgpKeyParsingKeyRingReader_initialize();
  return new_LibOrgBouncycastleOpenpgpPGPSecretKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(inputStream), new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init());
}

LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingCollectionWithJavaIoInputStream_(JavaIoInputStream *inputStream) {
  LibComAfterlogicPgpKeyParsingKeyRingReader_initialize();
  return new_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(inputStream), new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init());
}

LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *LibComAfterlogicPgpKeyParsingKeyRingReader_readKeyRingWithJavaIoInputStream_withJavaIoInputStream_(JavaIoInputStream *publicIn, JavaIoInputStream *secretIn) {
  LibComAfterlogicPgpKeyParsingKeyRingReader_initialize();
  if (publicIn == nil && secretIn == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"publicIn and secretIn cannot be BOTH null.");
  }
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing *publicKeys = nil;
  if (publicIn != nil) {
    publicKeys = LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingWithJavaIoInputStream_(publicIn);
  }
  LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys = nil;
  if (secretIn != nil) {
    secretKeys = LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingWithJavaIoInputStream_(secretIn);
  }
  if (secretKeys == nil) {
    return new_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(publicKeys);
  }
  if (publicKeys == nil) {
    return new_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(secretKeys);
  }
  return new_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(publicKeys, secretKeys);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyParsingKeyRingReader)
