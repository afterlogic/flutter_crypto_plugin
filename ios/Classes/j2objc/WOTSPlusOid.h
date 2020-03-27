//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/WOTSPlusOid.java
//

#ifndef WOTSPlusOid_H
#define WOTSPlusOid_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "XMSSOid.h"

@interface LibOrgBouncycastlePqcCryptoXmssWOTSPlusOid : NSObject < LibOrgBouncycastlePqcCryptoXmssXMSSOid >

#pragma mark Public

- (jint)getOid;

- (NSString *)description;

#pragma mark Protected

+ (LibOrgBouncycastlePqcCryptoXmssWOTSPlusOid *)lookupWithNSString:(NSString *)algorithmName
                                                           withInt:(jint)digestSize
                                                           withInt:(jint)winternitzParameter
                                                           withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssWOTSPlusOid)

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssWOTSPlusOid *LibOrgBouncycastlePqcCryptoXmssWOTSPlusOid_lookupWithNSString_withInt_withInt_withInt_(NSString *algorithmName, jint digestSize, jint winternitzParameter, jint len);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssWOTSPlusOid)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // WOTSPlusOid_H
