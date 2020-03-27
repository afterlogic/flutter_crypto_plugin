//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/keyring/impl/Email.java
//

#ifndef Email_H
#define Email_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PartialUserId.h"

@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPSecretKey;

@interface LibComAfterlogicPgpKeySelectionKeyringImplEmail : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplEmail)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplEmail_init(LibComAfterlogicPgpKeySelectionKeyringImplEmail *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplEmail *new_LibComAfterlogicPgpKeySelectionKeyringImplEmail_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplEmail *create_LibComAfterlogicPgpKeySelectionKeyringImplEmail_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplEmail)

@interface LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy : LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(NSString *)email
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplEmail_PubRingSelectionStrategy)

@interface LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy : LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(NSString *)email
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKey *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplEmail_SecRingSelectionStrategy)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Email_H
