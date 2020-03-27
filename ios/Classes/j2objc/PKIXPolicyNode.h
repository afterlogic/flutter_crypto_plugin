//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/PKIXPolicyNode.java
//

#ifndef PKIXPolicyNode_H
#define PKIXPolicyNode_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/cert/PolicyNode.h"

@protocol JavaUtilIterator;
@protocol JavaUtilList;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleJceProviderPKIXPolicyNode : NSObject < JavaSecurityCertPolicyNode > {
 @public
  id<JavaUtilList> children_;
  jint depth_;
  id<JavaUtilSet> expectedPolicies_;
  id<JavaSecurityCertPolicyNode> parent_;
  id<JavaUtilSet> policyQualifiers_;
  NSString *validPolicy_;
  jboolean critical_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaUtilList:(id<JavaUtilList>)_children
                                       withInt:(jint)_depth
                               withJavaUtilSet:(id<JavaUtilSet>)_expectedPolicies
                withJavaSecurityCertPolicyNode:(id<JavaSecurityCertPolicyNode>)_parent
                               withJavaUtilSet:(id<JavaUtilSet>)_policyQualifiers
                                  withNSString:(NSString *)_validPolicy
                                   withBoolean:(jboolean)_critical;

- (void)addChildWithLibOrgBouncycastleJceProviderPKIXPolicyNode:(LibOrgBouncycastleJceProviderPKIXPolicyNode *)_child;

- (id)java_clone;

- (LibOrgBouncycastleJceProviderPKIXPolicyNode *)copy__ OBJC_METHOD_FAMILY_NONE;

- (id<JavaUtilIterator>)getChildren;

- (jint)getDepth;

- (id<JavaUtilSet>)getExpectedPolicies;

- (id<JavaSecurityCertPolicyNode>)getParent;

- (id<JavaUtilSet>)getPolicyQualifiers;

- (NSString *)getValidPolicy;

- (jboolean)hasChildren;

- (jboolean)isCritical;

- (void)removeChildWithLibOrgBouncycastleJceProviderPKIXPolicyNode:(LibOrgBouncycastleJceProviderPKIXPolicyNode *)_child;

- (void)setCriticalWithBoolean:(jboolean)_critical;

- (void)setExpectedPoliciesWithJavaUtilSet:(id<JavaUtilSet>)expectedPolicies;

- (void)setParentWithLibOrgBouncycastleJceProviderPKIXPolicyNode:(LibOrgBouncycastleJceProviderPKIXPolicyNode *)_parent;

- (NSString *)description;

- (NSString *)toStringWithNSString:(NSString *)_indent;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderPKIXPolicyNode)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderPKIXPolicyNode, children_, id<JavaUtilList>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderPKIXPolicyNode, expectedPolicies_, id<JavaUtilSet>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderPKIXPolicyNode, parent_, id<JavaSecurityCertPolicyNode>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderPKIXPolicyNode, policyQualifiers_, id<JavaUtilSet>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderPKIXPolicyNode, validPolicy_, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderPKIXPolicyNode_initWithJavaUtilList_withInt_withJavaUtilSet_withJavaSecurityCertPolicyNode_withJavaUtilSet_withNSString_withBoolean_(LibOrgBouncycastleJceProviderPKIXPolicyNode *self, id<JavaUtilList> _children, jint _depth, id<JavaUtilSet> _expectedPolicies, id<JavaSecurityCertPolicyNode> _parent, id<JavaUtilSet> _policyQualifiers, NSString *_validPolicy, jboolean _critical);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPKIXPolicyNode *new_LibOrgBouncycastleJceProviderPKIXPolicyNode_initWithJavaUtilList_withInt_withJavaUtilSet_withJavaSecurityCertPolicyNode_withJavaUtilSet_withNSString_withBoolean_(id<JavaUtilList> _children, jint _depth, id<JavaUtilSet> _expectedPolicies, id<JavaSecurityCertPolicyNode> _parent, id<JavaUtilSet> _policyQualifiers, NSString *_validPolicy, jboolean _critical) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPKIXPolicyNode *create_LibOrgBouncycastleJceProviderPKIXPolicyNode_initWithJavaUtilList_withInt_withJavaUtilSet_withJavaSecurityCertPolicyNode_withJavaUtilSet_withNSString_withBoolean_(id<JavaUtilList> _children, jint _depth, id<JavaUtilSet> _expectedPolicies, id<JavaSecurityCertPolicyNode> _parent, id<JavaUtilSet> _policyQualifiers, NSString *_validPolicy, jboolean _critical);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderPKIXPolicyNode)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIXPolicyNode_H
