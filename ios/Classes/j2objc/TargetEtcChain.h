//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/TargetEtcChain.java
//

#ifndef TargetEtcChain_H
#define TargetEtcChain_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1DvcsCertEtcToken;
@class LibOrgBouncycastleAsn1DvcsPathProcInput;

@interface LibOrgBouncycastleAsn1DvcsTargetEtcChain : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DvcsCertEtcToken:(LibOrgBouncycastleAsn1DvcsCertEtcToken *)target;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DvcsCertEtcToken:(LibOrgBouncycastleAsn1DvcsCertEtcToken *)target
                         withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray:(IOSObjectArray *)chain;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DvcsCertEtcToken:(LibOrgBouncycastleAsn1DvcsCertEtcToken *)target
                         withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray:(IOSObjectArray *)chain
                             withLibOrgBouncycastleAsn1DvcsPathProcInput:(LibOrgBouncycastleAsn1DvcsPathProcInput *)pathProcInput;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DvcsCertEtcToken:(LibOrgBouncycastleAsn1DvcsCertEtcToken *)target
                             withLibOrgBouncycastleAsn1DvcsPathProcInput:(LibOrgBouncycastleAsn1DvcsPathProcInput *)pathProcInput;

+ (IOSObjectArray *)arrayFromSequenceWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (IOSObjectArray *)getChain;

+ (LibOrgBouncycastleAsn1DvcsTargetEtcChain *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DvcsTargetEtcChain *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1DvcsPathProcInput *)getPathProcInput;

- (LibOrgBouncycastleAsn1DvcsCertEtcToken *)getTarget;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DvcsTargetEtcChain)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_(LibOrgBouncycastleAsn1DvcsTargetEtcChain *self, LibOrgBouncycastleAsn1DvcsCertEtcToken *target);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *new_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *create_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray_(LibOrgBouncycastleAsn1DvcsTargetEtcChain *self, LibOrgBouncycastleAsn1DvcsCertEtcToken *target, IOSObjectArray *chain);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *new_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target, IOSObjectArray *chain) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *create_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target, IOSObjectArray *chain);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsPathProcInput_(LibOrgBouncycastleAsn1DvcsTargetEtcChain *self, LibOrgBouncycastleAsn1DvcsCertEtcToken *target, LibOrgBouncycastleAsn1DvcsPathProcInput *pathProcInput);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *new_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsPathProcInput_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target, LibOrgBouncycastleAsn1DvcsPathProcInput *pathProcInput) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *create_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsPathProcInput_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target, LibOrgBouncycastleAsn1DvcsPathProcInput *pathProcInput);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray_withLibOrgBouncycastleAsn1DvcsPathProcInput_(LibOrgBouncycastleAsn1DvcsTargetEtcChain *self, LibOrgBouncycastleAsn1DvcsCertEtcToken *target, IOSObjectArray *chain, LibOrgBouncycastleAsn1DvcsPathProcInput *pathProcInput);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *new_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray_withLibOrgBouncycastleAsn1DvcsPathProcInput_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target, IOSObjectArray *chain, LibOrgBouncycastleAsn1DvcsPathProcInput *pathProcInput) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *create_LibOrgBouncycastleAsn1DvcsTargetEtcChain_initWithLibOrgBouncycastleAsn1DvcsCertEtcToken_withLibOrgBouncycastleAsn1DvcsCertEtcTokenArray_withLibOrgBouncycastleAsn1DvcsPathProcInput_(LibOrgBouncycastleAsn1DvcsCertEtcToken *target, IOSObjectArray *chain, LibOrgBouncycastleAsn1DvcsPathProcInput *pathProcInput);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *LibOrgBouncycastleAsn1DvcsTargetEtcChain_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsTargetEtcChain *LibOrgBouncycastleAsn1DvcsTargetEtcChain_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleAsn1DvcsTargetEtcChain_arrayFromSequenceWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DvcsTargetEtcChain)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TargetEtcChain_H