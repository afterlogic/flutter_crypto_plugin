//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509CollectionStoreParameters.java
//

#ifndef X509CollectionStoreParameters_H
#define X509CollectionStoreParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "X509StoreParameters.h"

@protocol JavaUtilCollection;

@interface LibOrgBouncycastleX509X509CollectionStoreParameters : NSObject < LibOrgBouncycastleX509X509StoreParameters >

#pragma mark Public

- (instancetype __nonnull)initWithJavaUtilCollection:(id<JavaUtilCollection>)collection;

- (id)java_clone;

- (id<JavaUtilCollection>)getCollection;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509CollectionStoreParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509CollectionStoreParameters_initWithJavaUtilCollection_(LibOrgBouncycastleX509X509CollectionStoreParameters *self, id<JavaUtilCollection> collection);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CollectionStoreParameters *new_LibOrgBouncycastleX509X509CollectionStoreParameters_initWithJavaUtilCollection_(id<JavaUtilCollection> collection) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CollectionStoreParameters *create_LibOrgBouncycastleX509X509CollectionStoreParameters_initWithJavaUtilCollection_(id<JavaUtilCollection> collection);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509CollectionStoreParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509CollectionStoreParameters_H