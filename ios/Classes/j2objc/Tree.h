//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/sphincs/Tree.java
//

#ifndef Tree_H
#define Tree_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastlePqcCryptoSphincsHashFunctions;
@class LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr;

@interface LibOrgBouncycastlePqcCryptoSphincsTree : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (void)gen_leaf_wotsWithLibOrgBouncycastlePqcCryptoSphincsHashFunctions:(LibOrgBouncycastlePqcCryptoSphincsHashFunctions *)hs
                                                           withByteArray:(IOSByteArray *)leaf
                                                                 withInt:(jint)leafOff
                                                           withByteArray:(IOSByteArray *)masks
                                                                 withInt:(jint)masksOff
                                                           withByteArray:(IOSByteArray *)sk
                     withLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr:(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *)a;

+ (void)l_treeWithLibOrgBouncycastlePqcCryptoSphincsHashFunctions:(LibOrgBouncycastlePqcCryptoSphincsHashFunctions *)hs
                                                    withByteArray:(IOSByteArray *)leaf
                                                          withInt:(jint)leafOff
                                                    withByteArray:(IOSByteArray *)wots_pk
                                                          withInt:(jint)pkOff
                                                    withByteArray:(IOSByteArray *)masks
                                                          withInt:(jint)masksOff;

+ (void)treehashWithLibOrgBouncycastlePqcCryptoSphincsHashFunctions:(LibOrgBouncycastlePqcCryptoSphincsHashFunctions *)hs
                                                      withByteArray:(IOSByteArray *)node
                                                            withInt:(jint)nodeOff
                                                            withInt:(jint)height
                                                      withByteArray:(IOSByteArray *)sk
                withLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr:(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *)leaf
                                                      withByteArray:(IOSByteArray *)masks
                                                            withInt:(jint)masksOff;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoSphincsTree)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsTree_init(LibOrgBouncycastlePqcCryptoSphincsTree *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsTree *new_LibOrgBouncycastlePqcCryptoSphincsTree_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsTree *create_LibOrgBouncycastlePqcCryptoSphincsTree_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsTree_l_treeWithLibOrgBouncycastlePqcCryptoSphincsHashFunctions_withByteArray_withInt_withByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastlePqcCryptoSphincsHashFunctions *hs, IOSByteArray *leaf, jint leafOff, IOSByteArray *wots_pk, jint pkOff, IOSByteArray *masks, jint masksOff);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsTree_treehashWithLibOrgBouncycastlePqcCryptoSphincsHashFunctions_withByteArray_withInt_withInt_withByteArray_withLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_withByteArray_withInt_(LibOrgBouncycastlePqcCryptoSphincsHashFunctions *hs, IOSByteArray *node, jint nodeOff, jint height, IOSByteArray *sk, LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *leaf, IOSByteArray *masks, jint masksOff);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsTree_gen_leaf_wotsWithLibOrgBouncycastlePqcCryptoSphincsHashFunctions_withByteArray_withInt_withByteArray_withInt_withByteArray_withLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_(LibOrgBouncycastlePqcCryptoSphincsHashFunctions *hs, IOSByteArray *leaf, jint leafOff, IOSByteArray *masks, jint masksOff, IOSByteArray *sk, LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *a);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoSphincsTree)

@interface LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr : NSObject {
 @public
  jint level_;
  jlong subtree_;
  jlong subleaf_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr:(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *)leafaddr;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_init(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *new_LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *create_LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_initWithLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *self, LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *leafaddr);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *new_LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_initWithLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *leafaddr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *create_LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_initWithLibOrgBouncycastlePqcCryptoSphincsTree_leafaddr_(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr *leafaddr);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoSphincsTree_leafaddr)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Tree_H