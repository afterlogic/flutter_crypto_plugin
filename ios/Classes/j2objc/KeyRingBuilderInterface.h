//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/generation/KeyRingBuilderInterface.java
//

#ifndef KeyRingBuilderInterface_H
#define KeyRingBuilderInterface_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil;
@class LibComAfterlogicPgpKeyGenerationKeySpec;
@class LibComAfterlogicPgpUtilPassphrase;
@protocol LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_Build;
@protocol LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPassphrase;
@protocol LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPrimaryUserId;

@protocol LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface < JavaObject >

- (id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface>)withSubKeyWithLibComAfterlogicPgpKeyGenerationKeySpec:(LibComAfterlogicPgpKeyGenerationKeySpec *)keySpec;

- (id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPrimaryUserId>)withMasterKeyWithLibComAfterlogicPgpKeyGenerationKeySpec:(LibComAfterlogicPgpKeyGenerationKeySpec *)keySpec;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface)

@protocol LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPrimaryUserId < JavaObject >

- (id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPassphrase>)withPrimaryUserIdWithNSString:(NSString *)userId;

- (id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPassphrase>)withPrimaryUserIdWithByteArray:(IOSByteArray *)userId;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPrimaryUserId)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPrimaryUserId)

@protocol LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPassphrase < JavaObject >

- (id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_Build>)withPassphraseWithLibComAfterlogicPgpUtilPassphrase:(LibComAfterlogicPgpUtilPassphrase *)passphrase;

- (id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_Build>)withoutPassphrase;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPassphrase)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPassphrase)

@protocol LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_Build < JavaObject >

- (LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *)build;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_Build)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_Build)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyRingBuilderInterface_H