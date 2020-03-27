//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPSecretKeyRingCollection.java
//

#ifndef PGPSecretKeyRingCollection_H
#define PGPSecretKeyRingCollection_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "Iterable.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class LibOrgBouncycastleOpenpgpPGPSecretKey;
@class LibOrgBouncycastleOpenpgpPGPSecretKeyRing;
@protocol JavaUtilCollection;
@protocol JavaUtilFunctionConsumer;
@protocol JavaUtilIterator;
@protocol JavaUtilSpliterator;
@protocol LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;

@interface LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection : NSObject < LibOrgBouncycastleUtilIterable >

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoding
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator;

- (instancetype __nonnull)initWithJavaUtilCollection:(id<JavaUtilCollection>)collection;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator;

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)addSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)ringCollection
                                                                                   withLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRing;

- (jboolean)containsWithLong:(jlong)keyID;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream;

- (IOSByteArray *)getEncoded;

- (id<JavaUtilIterator>)getKeyRings;

- (id<JavaUtilIterator>)getKeyRingsWithNSString:(NSString *)userID;

- (id<JavaUtilIterator>)getKeyRingsWithNSString:(NSString *)userID
                                    withBoolean:(jboolean)matchPartial;

- (id<JavaUtilIterator>)getKeyRingsWithNSString:(NSString *)userID
                                    withBoolean:(jboolean)matchPartial
                                    withBoolean:(jboolean)ignoreCase;

- (LibOrgBouncycastleOpenpgpPGPSecretKey *)getSecretKeyWithLong:(jlong)keyID;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)getSecretKeyRingWithLong:(jlong)keyID;

- (id<JavaUtilIterator>)iterator;

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)removeSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)ringCollection
                                                                                      withLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeyRing;

- (jint)size;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *self, IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *self, JavaIoInputStream *inArg, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(JavaIoInputStream *inArg, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(JavaIoInputStream *inArg, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaUtilCollection_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *self, id<JavaUtilCollection> collection);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_addSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *ringCollection, LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeyRing);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_removeSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *ringCollection, LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeyRing);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPSecretKeyRingCollection_H
