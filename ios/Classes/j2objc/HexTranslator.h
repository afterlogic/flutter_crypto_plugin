//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/encoders/HexTranslator.java
//

#ifndef HexTranslator_H
#define HexTranslator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Translator.h"

@class IOSByteArray;

@interface LibOrgBouncycastleUtilEncodersHexTranslator : NSObject < LibOrgBouncycastleUtilEncodersTranslator >

#pragma mark Public

- (instancetype __nonnull)init;

- (jint)decodeWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)length
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)encodeWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)length
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)getDecodedBlockSize;

- (jint)getEncodedBlockSize;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleUtilEncodersHexTranslator)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilEncodersHexTranslator_init(LibOrgBouncycastleUtilEncodersHexTranslator *self);

FOUNDATION_EXPORT LibOrgBouncycastleUtilEncodersHexTranslator *new_LibOrgBouncycastleUtilEncodersHexTranslator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilEncodersHexTranslator *create_LibOrgBouncycastleUtilEncodersHexTranslator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilEncodersHexTranslator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // HexTranslator_H