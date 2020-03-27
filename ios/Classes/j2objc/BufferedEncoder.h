//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/encoders/BufferedEncoder.java
//

#ifndef BufferedEncoder_H
#define BufferedEncoder_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleUtilEncodersTranslator;

@interface LibOrgBouncycastleUtilEncodersBufferedEncoder : NSObject {
 @public
  IOSByteArray *buf_;
  jint bufOff_;
  id<LibOrgBouncycastleUtilEncodersTranslator> translator_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleUtilEncodersTranslator:(id<LibOrgBouncycastleUtilEncodersTranslator>)translator
                                                                   withInt:(jint)bufSize;

- (jint)processByteWithByte:(jbyte)inArg
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilEncodersBufferedEncoder)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilEncodersBufferedEncoder, buf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilEncodersBufferedEncoder, translator_, id<LibOrgBouncycastleUtilEncodersTranslator>)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilEncodersBufferedEncoder_initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_(LibOrgBouncycastleUtilEncodersBufferedEncoder *self, id<LibOrgBouncycastleUtilEncodersTranslator> translator, jint bufSize);

FOUNDATION_EXPORT LibOrgBouncycastleUtilEncodersBufferedEncoder *new_LibOrgBouncycastleUtilEncodersBufferedEncoder_initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_(id<LibOrgBouncycastleUtilEncodersTranslator> translator, jint bufSize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilEncodersBufferedEncoder *create_LibOrgBouncycastleUtilEncodersBufferedEncoder_initWithLibOrgBouncycastleUtilEncodersTranslator_withInt_(id<LibOrgBouncycastleUtilEncodersTranslator> translator, jint bufSize);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilEncodersBufferedEncoder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BufferedEncoder_H
