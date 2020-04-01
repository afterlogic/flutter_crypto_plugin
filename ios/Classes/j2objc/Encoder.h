//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/encoders/Encoder.java
//

#ifndef Encoder_H
#define Encoder_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoOutputStream;

@protocol LibOrgBouncycastleUtilEncodersEncoder < JavaObject >

- (jint)encodeWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)length
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

- (jint)decodeWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)length
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

- (jint)decodeWithNSString:(NSString *)data
    withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilEncodersEncoder)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilEncodersEncoder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Encoder_H