//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/interfaces/StateAwareSignature.java
//

#ifndef StateAwareSignature_H
#define StateAwareSignature_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaNioByteBuffer;
@class JavaSecurityCertCertificate;
@class JavaSecuritySecureRandom;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;

@protocol LibOrgBouncycastlePqcJcajceInterfacesStateAwareSignature < JavaObject >

- (void)initVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey OBJC_METHOD_FAMILY_NONE;

- (void)initVerifyWithJavaSecurityCertCertificate:(JavaSecurityCertCertificate *)certificate OBJC_METHOD_FAMILY_NONE;

- (void)initSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey OBJC_METHOD_FAMILY_NONE;

- (void)initSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey
              withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)sign;

- (jint)signWithByteArray:(IOSByteArray *)outbuf
                  withInt:(jint)offset
                  withInt:(jint)len;

- (jboolean)verifyWithByteArray:(IOSByteArray *)signature;

- (jboolean)verifyWithByteArray:(IOSByteArray *)signature
                        withInt:(jint)offset
                        withInt:(jint)length;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)data;

- (void)updateWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)len;

- (void)updateWithJavaNioByteBuffer:(JavaNioByteBuffer *)data;

- (NSString *)getAlgorithm;

- (jboolean)isSigningCapable;

- (id<JavaSecurityPrivateKey>)getUpdatedPrivateKey;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceInterfacesStateAwareSignature)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceInterfacesStateAwareSignature)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // StateAwareSignature_H
