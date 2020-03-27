//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509Store.java
//

#ifndef X509Store_H
#define X509Store_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Store.h"

@class JavaSecurityProvider;
@protocol JavaUtilCollection;
@protocol LibOrgBouncycastleUtilSelector;
@protocol LibOrgBouncycastleX509X509StoreParameters;

@interface LibOrgBouncycastleX509X509Store : NSObject < LibOrgBouncycastleUtilStore >

#pragma mark Public

+ (LibOrgBouncycastleX509X509Store *)getInstanceWithNSString:(NSString *)type
               withLibOrgBouncycastleX509X509StoreParameters:(id<LibOrgBouncycastleX509X509StoreParameters>)parameters;

+ (LibOrgBouncycastleX509X509Store *)getInstanceWithNSString:(NSString *)type
               withLibOrgBouncycastleX509X509StoreParameters:(id<LibOrgBouncycastleX509X509StoreParameters>)parameters
                                    withJavaSecurityProvider:(JavaSecurityProvider *)provider;

+ (LibOrgBouncycastleX509X509Store *)getInstanceWithNSString:(NSString *)type
               withLibOrgBouncycastleX509X509StoreParameters:(id<LibOrgBouncycastleX509X509StoreParameters>)parameters
                                                withNSString:(NSString *)provider;

- (id<JavaUtilCollection>)getMatchesWithLibOrgBouncycastleUtilSelector:(id<LibOrgBouncycastleUtilSelector>)selector;

- (JavaSecurityProvider *)getProvider;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509Store)

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Store *LibOrgBouncycastleX509X509Store_getInstanceWithNSString_withLibOrgBouncycastleX509X509StoreParameters_(NSString *type, id<LibOrgBouncycastleX509X509StoreParameters> parameters);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Store *LibOrgBouncycastleX509X509Store_getInstanceWithNSString_withLibOrgBouncycastleX509X509StoreParameters_withNSString_(NSString *type, id<LibOrgBouncycastleX509X509StoreParameters> parameters, NSString *provider);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Store *LibOrgBouncycastleX509X509Store_getInstanceWithNSString_withLibOrgBouncycastleX509X509StoreParameters_withJavaSecurityProvider_(NSString *type, id<LibOrgBouncycastleX509X509StoreParameters> parameters, JavaSecurityProvider *provider);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509Store)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509Store_H