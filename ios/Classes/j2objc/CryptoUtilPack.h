//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/CryptoUtilPack.java
//

#ifndef CryptoUtilPack_H
#define CryptoUtilPack_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSLongArray;

@interface LibOrgBouncycastleCryptoUtilCryptoUtilPack : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jint)bigEndianToIntWithByteArray:(IOSByteArray *)bs
                            withInt:(jint)off;

+ (void)bigEndianToIntWithByteArray:(IOSByteArray *)bs
                            withInt:(jint)off
                       withIntArray:(IOSIntArray *)ns;

+ (jlong)bigEndianToLongWithByteArray:(IOSByteArray *)bs
                              withInt:(jint)off;

+ (void)bigEndianToLongWithByteArray:(IOSByteArray *)bs
                             withInt:(jint)off
                       withLongArray:(IOSLongArray *)ns;

+ (IOSByteArray *)intToBigEndianWithInt:(jint)n;

+ (void)intToBigEndianWithInt:(jint)n
                withByteArray:(IOSByteArray *)bs
                      withInt:(jint)off;

+ (IOSByteArray *)intToBigEndianWithIntArray:(IOSIntArray *)ns;

+ (void)intToBigEndianWithIntArray:(IOSIntArray *)ns
                     withByteArray:(IOSByteArray *)bs
                           withInt:(jint)off;

+ (IOSByteArray *)intToLittleEndianWithInt:(jint)n;

+ (void)intToLittleEndianWithInt:(jint)n
                   withByteArray:(IOSByteArray *)bs
                         withInt:(jint)off;

+ (IOSByteArray *)intToLittleEndianWithIntArray:(IOSIntArray *)ns;

+ (void)intToLittleEndianWithIntArray:(IOSIntArray *)ns
                        withByteArray:(IOSByteArray *)bs
                              withInt:(jint)off;

+ (jint)littleEndianToIntWithByteArray:(IOSByteArray *)bs
                               withInt:(jint)off;

+ (void)littleEndianToIntWithByteArray:(IOSByteArray *)bs
                               withInt:(jint)off
                          withIntArray:(IOSIntArray *)ns;

+ (void)littleEndianToIntWithByteArray:(IOSByteArray *)bs
                               withInt:(jint)bOff
                          withIntArray:(IOSIntArray *)ns
                               withInt:(jint)nOff
                               withInt:(jint)count;

+ (jlong)littleEndianToLongWithByteArray:(IOSByteArray *)bs
                                 withInt:(jint)off;

+ (void)littleEndianToLongWithByteArray:(IOSByteArray *)bs
                                withInt:(jint)off
                          withLongArray:(IOSLongArray *)ns;

+ (IOSByteArray *)longToBigEndianWithLong:(jlong)n;

+ (void)longToBigEndianWithLong:(jlong)n
                  withByteArray:(IOSByteArray *)bs
                        withInt:(jint)off;

+ (IOSByteArray *)longToBigEndianWithLongArray:(IOSLongArray *)ns;

+ (void)longToBigEndianWithLongArray:(IOSLongArray *)ns
                       withByteArray:(IOSByteArray *)bs
                             withInt:(jint)off;

+ (IOSByteArray *)longToLittleEndianWithLong:(jlong)n;

+ (void)longToLittleEndianWithLong:(jlong)n
                     withByteArray:(IOSByteArray *)bs
                           withInt:(jint)off;

+ (IOSByteArray *)longToLittleEndianWithLongArray:(IOSLongArray *)ns;

+ (void)longToLittleEndianWithLongArray:(IOSLongArray *)ns
                          withByteArray:(IOSByteArray *)bs
                                withInt:(jint)off;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoUtilCryptoUtilPack)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_init(LibOrgBouncycastleCryptoUtilCryptoUtilPack *self);

FOUNDATION_EXPORT jint LibOrgBouncycastleCryptoUtilCryptoUtilPack_bigEndianToIntWithByteArray_withInt_(IOSByteArray *bs, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_bigEndianToIntWithByteArray_withInt_withIntArray_(IOSByteArray *bs, jint off, IOSIntArray *ns);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToBigEndianWithInt_(jint n);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToBigEndianWithInt_withByteArray_withInt_(jint n, IOSByteArray *bs, jint off);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToBigEndianWithIntArray_(IOSIntArray *ns);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToBigEndianWithIntArray_withByteArray_withInt_(IOSIntArray *ns, IOSByteArray *bs, jint off);

FOUNDATION_EXPORT jlong LibOrgBouncycastleCryptoUtilCryptoUtilPack_bigEndianToLongWithByteArray_withInt_(IOSByteArray *bs, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_bigEndianToLongWithByteArray_withInt_withLongArray_(IOSByteArray *bs, jint off, IOSLongArray *ns);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToBigEndianWithLong_(jlong n);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToBigEndianWithLong_withByteArray_withInt_(jlong n, IOSByteArray *bs, jint off);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToBigEndianWithLongArray_(IOSLongArray *ns);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToBigEndianWithLongArray_withByteArray_withInt_(IOSLongArray *ns, IOSByteArray *bs, jint off);

FOUNDATION_EXPORT jint LibOrgBouncycastleCryptoUtilCryptoUtilPack_littleEndianToIntWithByteArray_withInt_(IOSByteArray *bs, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_littleEndianToIntWithByteArray_withInt_withIntArray_(IOSByteArray *bs, jint off, IOSIntArray *ns);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_littleEndianToIntWithByteArray_withInt_withIntArray_withInt_withInt_(IOSByteArray *bs, jint bOff, IOSIntArray *ns, jint nOff, jint count);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToLittleEndianWithInt_(jint n);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(jint n, IOSByteArray *bs, jint off);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToLittleEndianWithIntArray_(IOSIntArray *ns);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_intToLittleEndianWithIntArray_withByteArray_withInt_(IOSIntArray *ns, IOSByteArray *bs, jint off);

FOUNDATION_EXPORT jlong LibOrgBouncycastleCryptoUtilCryptoUtilPack_littleEndianToLongWithByteArray_withInt_(IOSByteArray *bs, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_littleEndianToLongWithByteArray_withInt_withLongArray_(IOSByteArray *bs, jint off, IOSLongArray *ns);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToLittleEndianWithLong_(jlong n);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToLittleEndianWithLong_withByteArray_withInt_(jlong n, IOSByteArray *bs, jint off);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToLittleEndianWithLongArray_(IOSLongArray *ns);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilCryptoUtilPack_longToLittleEndianWithLongArray_withByteArray_withInt_(IOSLongArray *ns, IOSByteArray *bs, jint off);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoUtilCryptoUtilPack)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CryptoUtilPack_H
