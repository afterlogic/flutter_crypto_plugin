//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/parsing/KeyRingReader.java
//

#ifndef KeyRingReader_H
#define KeyRingReader_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaNioCharsetCharset;
@class LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRing;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;
@class LibOrgBouncycastleOpenpgpPGPSecretKeyRing;
@class LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;

@interface LibComAfterlogicPgpKeyParsingKeyRingReader : NSObject
@property (readonly, class) JavaNioCharsetCharset *UTF8 NS_SWIFT_NAME(UTF8);

+ (JavaNioCharsetCharset *)UTF8;

#pragma mark Public

- (instancetype __nonnull)init;

- (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)keyRingWithByteArray:(IOSByteArray *)publicBytes
                                                           withByteArray:(IOSByteArray *)secretBytes;

- (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)keyRingWithJavaIoInputStream:(JavaIoInputStream *)publicIn
                                                           withJavaIoInputStream:(JavaIoInputStream *)secretIn;

- (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)keyRingWithNSString:(NSString *)asciiPublic
                                                           withNSString:(NSString *)asciiSecret;

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingWithByteArray:(IOSByteArray *)bytes;

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingWithNSString:(NSString *)asciiArmored;

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRingCollectionWithByteArray:(IOSByteArray *)bytes;

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRingCollectionWithNSString:(NSString *)asciiArmored;

+ (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)readKeyRingWithJavaIoInputStream:(JavaIoInputStream *)publicIn
                                                               withJavaIoInputStream:(JavaIoInputStream *)secretIn;

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)readPublicKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)readPublicKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)readSecretKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)readSecretKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRingWithByteArray:(IOSByteArray *)bytes;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRingWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRingWithNSString:(NSString *)asciiArmored;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRingCollectionWithByteArray:(IOSByteArray *)bytes;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRingCollectionWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRingCollectionWithNSString:(NSString *)asciiArmored;

@end

J2OBJC_STATIC_INIT(LibComAfterlogicPgpKeyParsingKeyRingReader)

inline JavaNioCharsetCharset *LibComAfterlogicPgpKeyParsingKeyRingReader_get_UTF8(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaNioCharsetCharset *LibComAfterlogicPgpKeyParsingKeyRingReader_UTF8;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibComAfterlogicPgpKeyParsingKeyRingReader, UTF8, JavaNioCharsetCharset *)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeyParsingKeyRingReader_init(LibComAfterlogicPgpKeyParsingKeyRingReader *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyParsingKeyRingReader *new_LibComAfterlogicPgpKeyParsingKeyRingReader_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeyParsingKeyRingReader *create_LibComAfterlogicPgpKeyParsingKeyRingReader_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingWithJavaIoInputStream_(JavaIoInputStream *inputStream);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingCollectionWithJavaIoInputStream_(JavaIoInputStream *inputStream);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRing *LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingWithJavaIoInputStream_(JavaIoInputStream *inputStream);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingCollectionWithJavaIoInputStream_(JavaIoInputStream *inputStream);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *LibComAfterlogicPgpKeyParsingKeyRingReader_readKeyRingWithJavaIoInputStream_withJavaIoInputStream_(JavaIoInputStream *publicIn, JavaIoInputStream *secretIn);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyParsingKeyRingReader)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyRingReader_H