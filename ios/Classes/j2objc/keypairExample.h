//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/example/keypairExample.java
//

#ifndef KeypairExample_H
#define KeypairExample_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSCharArray;
@class IOSObjectArray;

@interface LibOrgBouncycastleExamplekeypairExample : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (IOSObjectArray *)generateKeyRingWithNSString:(NSString *)identity
                                  withCharArray:(IOSCharArray *)passphrase;

+ (void)mainWithNSStringArray:(IOSObjectArray *)args;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleExamplekeypairExample)

FOUNDATION_EXPORT void LibOrgBouncycastleExamplekeypairExample_init(LibOrgBouncycastleExamplekeypairExample *self);

FOUNDATION_EXPORT LibOrgBouncycastleExamplekeypairExample *new_LibOrgBouncycastleExamplekeypairExample_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleExamplekeypairExample *create_LibOrgBouncycastleExamplekeypairExample_init(void);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleExamplekeypairExample_generateKeyRingWithNSString_withCharArray_(NSString *identity, IOSCharArray *passphrase);

FOUNDATION_EXPORT void LibOrgBouncycastleExamplekeypairExample_mainWithNSStringArray_(IOSObjectArray *args);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleExamplekeypairExample)

@compatibility_alias LibOrgBouncycastleExampleKeypairExample LibOrgBouncycastleExamplekeypairExample;


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeypairExample_H