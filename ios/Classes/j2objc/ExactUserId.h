//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/keyring/impl/ExactUserId.java
//

#ifndef ExactUserId_H
#define ExactUserId_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PublicKeyRingSelectionStrategy.h"
#include "SecretKeyRingSelectionStrategy.h"

@class LibOrgBouncycastleOpenpgpPGPPublicKeyRing;
@class LibOrgBouncycastleOpenpgpPGPSecretKeyRing;

@interface LibComAfterlogicPgpKeySelectionKeyringImplExactUserId : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_init(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplExactUserId *new_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplExactUserId *create_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId)

@interface LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy : LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(NSString *)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)keyRing;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy)

@interface LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy : LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(NSString *)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)keyRing;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ExactUserId_H
