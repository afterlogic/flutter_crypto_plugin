//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/CertPathValidatorUtilities.java
//

#ifndef CertPathValidatorUtilities_H
#define CertPathValidatorUtilities_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaSecurityCertPKIXParameters;
@class JavaSecurityCertX509CRL;
@class JavaSecurityCertX509Certificate;
@class JavaUtilDate;
@class JavaxSecurityAuthX500X500Principal;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastleJcajcePKIXCertStoreSelector;
@class LibOrgBouncycastleJceProviderPKIXPolicyNode;
@class LibOrgBouncycastleX509CertStatus;
@class LibOrgBouncycastleX509PKIXCRLUtil;
@class LibOrgBouncycastleX509X509AttributeCertStoreSelector;
@class LibOrgBouncycastleX509X509CertStoreSelector;
@protocol JavaSecurityCertX509Extension;
@protocol JavaSecurityPublicKey;
@protocol JavaUtilCollection;
@protocol JavaUtilList;
@protocol JavaUtilMap;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleX509CertPathValidatorUtilities : NSObject
@property (readonly, class) LibOrgBouncycastleX509PKIXCRLUtil *CRL_UTIL NS_SWIFT_NAME(CRL_UTIL);
@property (readonly, copy, class) NSString *CERTIFICATE_POLICIES NS_SWIFT_NAME(CERTIFICATE_POLICIES);
@property (readonly, copy, class) NSString *BASIC_CONSTRAINTS NS_SWIFT_NAME(BASIC_CONSTRAINTS);
@property (readonly, copy, class) NSString *POLICY_MAPPINGS NS_SWIFT_NAME(POLICY_MAPPINGS);
@property (readonly, copy, class) NSString *SUBJECT_ALTERNATIVE_NAME NS_SWIFT_NAME(SUBJECT_ALTERNATIVE_NAME);
@property (readonly, copy, class) NSString *NAME_CONSTRAINTS NS_SWIFT_NAME(NAME_CONSTRAINTS);
@property (readonly, copy, class) NSString *KEY_USAGE NS_SWIFT_NAME(KEY_USAGE);
@property (readonly, copy, class) NSString *INHIBIT_ANY_POLICY NS_SWIFT_NAME(INHIBIT_ANY_POLICY);
@property (readonly, copy, class) NSString *ISSUING_DISTRIBUTION_POINT NS_SWIFT_NAME(ISSUING_DISTRIBUTION_POINT);
@property (readonly, copy, class) NSString *DELTA_CRL_INDICATOR NS_SWIFT_NAME(DELTA_CRL_INDICATOR);
@property (readonly, copy, class) NSString *POLICY_CONSTRAINTS NS_SWIFT_NAME(POLICY_CONSTRAINTS);
@property (readonly, copy, class) NSString *FRESHEST_CRL NS_SWIFT_NAME(FRESHEST_CRL);
@property (readonly, copy, class) NSString *CRL_DISTRIBUTION_POINTS NS_SWIFT_NAME(CRL_DISTRIBUTION_POINTS);
@property (readonly, copy, class) NSString *AUTHORITY_KEY_IDENTIFIER NS_SWIFT_NAME(AUTHORITY_KEY_IDENTIFIER);
@property (readonly, copy, class) NSString *ANY_POLICY NS_SWIFT_NAME(ANY_POLICY);
@property (readonly, copy, class) NSString *CRL_NUMBER NS_SWIFT_NAME(CRL_NUMBER);
@property (readonly, class) jint KEY_CERT_SIGN NS_SWIFT_NAME(KEY_CERT_SIGN);
@property (readonly, class) jint CRL_SIGN NS_SWIFT_NAME(CRL_SIGN);
@property (readonly, class) IOSObjectArray *crlReasons NS_SWIFT_NAME(crlReasons);

+ (LibOrgBouncycastleX509PKIXCRLUtil *)CRL_UTIL;

+ (NSString *)CERTIFICATE_POLICIES;

+ (NSString *)BASIC_CONSTRAINTS;

+ (NSString *)POLICY_MAPPINGS;

+ (NSString *)SUBJECT_ALTERNATIVE_NAME;

+ (NSString *)NAME_CONSTRAINTS;

+ (NSString *)KEY_USAGE;

+ (NSString *)INHIBIT_ANY_POLICY;

+ (NSString *)ISSUING_DISTRIBUTION_POINT;

+ (NSString *)DELTA_CRL_INDICATOR;

+ (NSString *)POLICY_CONSTRAINTS;

+ (NSString *)FRESHEST_CRL;

+ (NSString *)CRL_DISTRIBUTION_POINTS;

+ (NSString *)AUTHORITY_KEY_IDENTIFIER;

+ (NSString *)ANY_POLICY;

+ (NSString *)CRL_NUMBER;

+ (jint)KEY_CERT_SIGN;

+ (jint)CRL_SIGN;

+ (IOSObjectArray *)crlReasons;

#pragma mark Protected

+ (id<JavaUtilCollection>)findCertificatesWithLibOrgBouncycastleJcajcePKIXCertStoreSelector:(LibOrgBouncycastleJcajcePKIXCertStoreSelector *)certSelect
                                                                           withJavaUtilList:(id<JavaUtilList>)certStores;

+ (id<JavaUtilCollection>)findCertificatesWithLibOrgBouncycastleX509X509AttributeCertStoreSelector:(LibOrgBouncycastleX509X509AttributeCertStoreSelector *)certSelect
                                                                                  withJavaUtilList:(id<JavaUtilList>)certStores;

+ (id<JavaUtilCollection>)findCertificatesWithLibOrgBouncycastleX509X509CertStoreSelector:(LibOrgBouncycastleX509X509CertStoreSelector *)certSelect
                                                                         withJavaUtilList:(id<JavaUtilList>)certStores;

+ (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getAlgorithmIdentifierWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

+ (void)getCertStatusWithJavaUtilDate:(JavaUtilDate *)validDate
          withJavaSecurityCertX509CRL:(JavaSecurityCertX509CRL *)crl
                               withId:(id)cert
 withLibOrgBouncycastleX509CertStatus:(LibOrgBouncycastleX509CertStatus *)certStatus;

+ (JavaxSecurityAuthX500X500Principal *)getEncodedIssuerPrincipalWithId:(id)cert;

+ (LibOrgBouncycastleAsn1ASN1Primitive *)getExtensionValueWithJavaSecurityCertX509Extension:(id<JavaSecurityCertX509Extension>)ext
                                                                               withNSString:(NSString *)oid;

+ (JavaxSecurityAuthX500X500Principal *)getIssuerPrincipalWithJavaSecurityCertX509CRL:(JavaSecurityCertX509CRL *)crl;

+ (id<JavaSecurityPublicKey>)getNextWorkingKeyWithJavaUtilList:(id<JavaUtilList>)certs
                                                       withInt:(jint)index;

+ (id<JavaUtilSet>)getQualifierSetWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)qualifiers;

+ (JavaxSecurityAuthX500X500Principal *)getSubjectPrincipalWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert;

+ (JavaUtilDate *)getValidDateWithJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)paramsPKIX;

+ (jboolean)isAnyPolicyWithJavaUtilSet:(id<JavaUtilSet>)policySet;

+ (jboolean)isSelfIssuedWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert;

+ (void)prepareNextCertB1WithInt:(jint)i
           withJavaUtilListArray:(IOSObjectArray *)policyNodes
                    withNSString:(NSString *)id_p
                 withJavaUtilMap:(id<JavaUtilMap>)m_idp
withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert;

+ (LibOrgBouncycastleJceProviderPKIXPolicyNode *)prepareNextCertB2WithInt:(jint)i
                                                    withJavaUtilListArray:(IOSObjectArray *)policyNodes
                                                             withNSString:(NSString *)id_p
                          withLibOrgBouncycastleJceProviderPKIXPolicyNode:(LibOrgBouncycastleJceProviderPKIXPolicyNode *)validPolicyTree;

+ (jboolean)processCertD1iWithInt:(jint)index
            withJavaUtilListArray:(IOSObjectArray *)policyNodes
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)pOid
                  withJavaUtilSet:(id<JavaUtilSet>)pq;

+ (void)processCertD1iiWithInt:(jint)index
         withJavaUtilListArray:(IOSObjectArray *)policyNodes
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)_poid
               withJavaUtilSet:(id<JavaUtilSet>)_pq;

+ (LibOrgBouncycastleJceProviderPKIXPolicyNode *)removePolicyNodeWithLibOrgBouncycastleJceProviderPKIXPolicyNode:(LibOrgBouncycastleJceProviderPKIXPolicyNode *)validPolicyTree
                                                                                           withJavaUtilListArray:(IOSObjectArray *)policyNodes
                                                                 withLibOrgBouncycastleJceProviderPKIXPolicyNode:(LibOrgBouncycastleJceProviderPKIXPolicyNode *)_node;

+ (void)verifyX509CertificateWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert
                                       withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey
                                                    withNSString:(NSString *)sigProvider;

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (jboolean)isIndirectCRLWithJavaSecurityCertX509CRL:(JavaSecurityCertX509CRL *)crl;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleX509CertPathValidatorUtilities)

inline LibOrgBouncycastleX509PKIXCRLUtil *LibOrgBouncycastleX509CertPathValidatorUtilities_get_CRL_UTIL(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleX509PKIXCRLUtil *LibOrgBouncycastleX509CertPathValidatorUtilities_CRL_UTIL;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, CRL_UTIL, LibOrgBouncycastleX509PKIXCRLUtil *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_CERTIFICATE_POLICIES(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_CERTIFICATE_POLICIES;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, CERTIFICATE_POLICIES, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_BASIC_CONSTRAINTS(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_BASIC_CONSTRAINTS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, BASIC_CONSTRAINTS, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_POLICY_MAPPINGS(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_POLICY_MAPPINGS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, POLICY_MAPPINGS, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_SUBJECT_ALTERNATIVE_NAME(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_SUBJECT_ALTERNATIVE_NAME;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, SUBJECT_ALTERNATIVE_NAME, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_NAME_CONSTRAINTS(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_NAME_CONSTRAINTS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, NAME_CONSTRAINTS, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_KEY_USAGE(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_KEY_USAGE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, KEY_USAGE, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_INHIBIT_ANY_POLICY(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_INHIBIT_ANY_POLICY;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, INHIBIT_ANY_POLICY, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_ISSUING_DISTRIBUTION_POINT(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_ISSUING_DISTRIBUTION_POINT;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, ISSUING_DISTRIBUTION_POINT, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_DELTA_CRL_INDICATOR(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_DELTA_CRL_INDICATOR;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, DELTA_CRL_INDICATOR, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_POLICY_CONSTRAINTS(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_POLICY_CONSTRAINTS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, POLICY_CONSTRAINTS, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_FRESHEST_CRL(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_FRESHEST_CRL;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, FRESHEST_CRL, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_CRL_DISTRIBUTION_POINTS(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_CRL_DISTRIBUTION_POINTS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, CRL_DISTRIBUTION_POINTS, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_AUTHORITY_KEY_IDENTIFIER(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_AUTHORITY_KEY_IDENTIFIER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, AUTHORITY_KEY_IDENTIFIER, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_ANY_POLICY(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_ANY_POLICY;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, ANY_POLICY, NSString *)

inline NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_get_CRL_NUMBER(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleX509CertPathValidatorUtilities_CRL_NUMBER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, CRL_NUMBER, NSString *)

inline jint LibOrgBouncycastleX509CertPathValidatorUtilities_get_KEY_CERT_SIGN(void);
#define LibOrgBouncycastleX509CertPathValidatorUtilities_KEY_CERT_SIGN 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleX509CertPathValidatorUtilities, KEY_CERT_SIGN, jint)

inline jint LibOrgBouncycastleX509CertPathValidatorUtilities_get_CRL_SIGN(void);
#define LibOrgBouncycastleX509CertPathValidatorUtilities_CRL_SIGN 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleX509CertPathValidatorUtilities, CRL_SIGN, jint)

inline IOSObjectArray *LibOrgBouncycastleX509CertPathValidatorUtilities_get_crlReasons(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleX509CertPathValidatorUtilities_crlReasons;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleX509CertPathValidatorUtilities, crlReasons, IOSObjectArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathValidatorUtilities_init(LibOrgBouncycastleX509CertPathValidatorUtilities *self);

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathValidatorUtilities *new_LibOrgBouncycastleX509CertPathValidatorUtilities_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathValidatorUtilities *create_LibOrgBouncycastleX509CertPathValidatorUtilities_init(void);

FOUNDATION_EXPORT JavaxSecurityAuthX500X500Principal *LibOrgBouncycastleX509CertPathValidatorUtilities_getEncodedIssuerPrincipalWithId_(id cert);

FOUNDATION_EXPORT JavaUtilDate *LibOrgBouncycastleX509CertPathValidatorUtilities_getValidDateWithJavaSecurityCertPKIXParameters_(JavaSecurityCertPKIXParameters *paramsPKIX);

FOUNDATION_EXPORT JavaxSecurityAuthX500X500Principal *LibOrgBouncycastleX509CertPathValidatorUtilities_getSubjectPrincipalWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleX509CertPathValidatorUtilities_isSelfIssuedWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleX509CertPathValidatorUtilities_getExtensionValueWithJavaSecurityCertX509Extension_withNSString_(id<JavaSecurityCertX509Extension> ext, NSString *oid);

FOUNDATION_EXPORT JavaxSecurityAuthX500X500Principal *LibOrgBouncycastleX509CertPathValidatorUtilities_getIssuerPrincipalWithJavaSecurityCertX509CRL_(JavaSecurityCertX509CRL *crl);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509AlgorithmIdentifier *LibOrgBouncycastleX509CertPathValidatorUtilities_getAlgorithmIdentifierWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key);

FOUNDATION_EXPORT id<JavaUtilSet> LibOrgBouncycastleX509CertPathValidatorUtilities_getQualifierSetWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *qualifiers);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPKIXPolicyNode *LibOrgBouncycastleX509CertPathValidatorUtilities_removePolicyNodeWithLibOrgBouncycastleJceProviderPKIXPolicyNode_withJavaUtilListArray_withLibOrgBouncycastleJceProviderPKIXPolicyNode_(LibOrgBouncycastleJceProviderPKIXPolicyNode *validPolicyTree, IOSObjectArray *policyNodes, LibOrgBouncycastleJceProviderPKIXPolicyNode *_node);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleX509CertPathValidatorUtilities_processCertD1iWithInt_withJavaUtilListArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaUtilSet_(jint index, IOSObjectArray *policyNodes, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *pOid, id<JavaUtilSet> pq);

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathValidatorUtilities_processCertD1iiWithInt_withJavaUtilListArray_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaUtilSet_(jint index, IOSObjectArray *policyNodes, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *_poid, id<JavaUtilSet> _pq);

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathValidatorUtilities_prepareNextCertB1WithInt_withJavaUtilListArray_withNSString_withJavaUtilMap_withJavaSecurityCertX509Certificate_(jint i, IOSObjectArray *policyNodes, NSString *id_p, id<JavaUtilMap> m_idp, JavaSecurityCertX509Certificate *cert);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPKIXPolicyNode *LibOrgBouncycastleX509CertPathValidatorUtilities_prepareNextCertB2WithInt_withJavaUtilListArray_withNSString_withLibOrgBouncycastleJceProviderPKIXPolicyNode_(jint i, IOSObjectArray *policyNodes, NSString *id_p, LibOrgBouncycastleJceProviderPKIXPolicyNode *validPolicyTree);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleX509CertPathValidatorUtilities_isAnyPolicyWithJavaUtilSet_(id<JavaUtilSet> policySet);

FOUNDATION_EXPORT id<JavaUtilCollection> LibOrgBouncycastleX509CertPathValidatorUtilities_findCertificatesWithLibOrgBouncycastleX509X509CertStoreSelector_withJavaUtilList_(LibOrgBouncycastleX509X509CertStoreSelector *certSelect, id<JavaUtilList> certStores);

FOUNDATION_EXPORT id<JavaUtilCollection> LibOrgBouncycastleX509CertPathValidatorUtilities_findCertificatesWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_withJavaUtilList_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *certSelect, id<JavaUtilList> certStores);

FOUNDATION_EXPORT id<JavaUtilCollection> LibOrgBouncycastleX509CertPathValidatorUtilities_findCertificatesWithLibOrgBouncycastleX509X509AttributeCertStoreSelector_withJavaUtilList_(LibOrgBouncycastleX509X509AttributeCertStoreSelector *certSelect, id<JavaUtilList> certStores);

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathValidatorUtilities_getCertStatusWithJavaUtilDate_withJavaSecurityCertX509CRL_withId_withLibOrgBouncycastleX509CertStatus_(JavaUtilDate *validDate, JavaSecurityCertX509CRL *crl, id cert, LibOrgBouncycastleX509CertStatus *certStatus);

FOUNDATION_EXPORT id<JavaSecurityPublicKey> LibOrgBouncycastleX509CertPathValidatorUtilities_getNextWorkingKeyWithJavaUtilList_withInt_(id<JavaUtilList> certs, jint index);

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathValidatorUtilities_verifyX509CertificateWithJavaSecurityCertX509Certificate_withJavaSecurityPublicKey_withNSString_(JavaSecurityCertX509Certificate *cert, id<JavaSecurityPublicKey> publicKey, NSString *sigProvider);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleX509CertPathValidatorUtilities_isIndirectCRLWithJavaSecurityCertX509CRL_(JavaSecurityCertX509CRL *crl);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509CertPathValidatorUtilities)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertPathValidatorUtilities_H