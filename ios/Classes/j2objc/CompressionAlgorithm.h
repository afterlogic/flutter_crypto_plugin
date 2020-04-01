//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/algorithm/CompressionAlgorithm.java
//

#ifndef CompressionAlgorithm_H
#define CompressionAlgorithm_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/Enum.h"

@class IOSObjectArray;

typedef NS_ENUM(NSUInteger, LibComAfterlogicPgpAlgorithmCompressionAlgorithm_Enum) {
  LibComAfterlogicPgpAlgorithmCompressionAlgorithm_Enum_UNCOMPRESSED = 0,
  LibComAfterlogicPgpAlgorithmCompressionAlgorithm_Enum_ZIP = 1,
  LibComAfterlogicPgpAlgorithmCompressionAlgorithm_Enum_ZLIB = 2,
  LibComAfterlogicPgpAlgorithmCompressionAlgorithm_Enum_BZIP2 = 3,
};

@interface LibComAfterlogicPgpAlgorithmCompressionAlgorithm : JavaLangEnum

@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmCompressionAlgorithm *UNCOMPRESSED NS_SWIFT_NAME(UNCOMPRESSED);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmCompressionAlgorithm *ZIP NS_SWIFT_NAME(ZIP);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmCompressionAlgorithm *ZLIB NS_SWIFT_NAME(ZLIB);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmCompressionAlgorithm *BZIP2 NS_SWIFT_NAME(BZIP2);
+ (LibComAfterlogicPgpAlgorithmCompressionAlgorithm * __nonnull)UNCOMPRESSED;

+ (LibComAfterlogicPgpAlgorithmCompressionAlgorithm * __nonnull)ZIP;

+ (LibComAfterlogicPgpAlgorithmCompressionAlgorithm * __nonnull)ZLIB;

+ (LibComAfterlogicPgpAlgorithmCompressionAlgorithm * __nonnull)BZIP2;

#pragma mark Public

+ (LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)fromIdWithInt:(jint)id_;

- (jint)getAlgorithmId;

+ (LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

#pragma mark Package-Private

- (LibComAfterlogicPgpAlgorithmCompressionAlgorithm_Enum)toNSEnum;

@end

J2OBJC_STATIC_INIT(LibComAfterlogicPgpAlgorithmCompressionAlgorithm)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_values_[];

inline LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_get_UNCOMPRESSED(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmCompressionAlgorithm, UNCOMPRESSED)

inline LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_get_ZIP(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmCompressionAlgorithm, ZIP)

inline LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_get_ZLIB(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmCompressionAlgorithm, ZLIB)

inline LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_get_BZIP2(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmCompressionAlgorithm, BZIP2)

FOUNDATION_EXPORT LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_fromIdWithInt_(jint id_);

FOUNDATION_EXPORT IOSObjectArray *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_values(void);

FOUNDATION_EXPORT LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT LibComAfterlogicPgpAlgorithmCompressionAlgorithm *LibComAfterlogicPgpAlgorithmCompressionAlgorithm_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpAlgorithmCompressionAlgorithm)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CompressionAlgorithm_H