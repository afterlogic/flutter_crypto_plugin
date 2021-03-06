package com.afterlogic.crypto_plugin.pgp


import KeyDescription
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator
import org.bouncycastle.openpgp.operator.bc.*
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.decryption_verification.DecryptionBuilder
import org.pgpainless.decryption_verification.DecryptionStream
import org.pgpainless.encryption_signing.EncryptionBuilder
import org.pgpainless.encryption_signing.EncryptionStream
import org.pgpainless.key.generation.type.RSA_GENERAL
import org.pgpainless.key.generation.type.length.RsaLength
import org.pgpainless.key.parsing.KeyRingReader
import org.pgpainless.key.protection.KeyRingProtectionSettings
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector
import org.pgpainless.key.protection.SecretKeyPassphraseProvider
import org.pgpainless.util.BCUtil
import org.pgpainless.util.Passphrase
import java.io.*
import java.security.NoSuchProviderException
import java.security.SecureRandom
import java.security.Security
import java.util.*
import kotlin.collections.ArrayList


class Pgp {
    private val digestCalculator = BcPGPDigestCalculatorProvider()
    private val provider = BouncyCastleProvider()
    private val calculator: KeyFingerPrintCalculator = BcKeyFingerprintCalculator()
    var lastVerifyResult: Boolean? = null
        private set
    var progress: Progress? = null
        private set

    init {
        Security.addProvider(provider)
    }

    @Throws(IOException::class, PGPException::class)
    fun readPublicKey(inputStream: InputStream): PGPPublicKey {
        var inputStream1 = inputStream
        inputStream1 = PGPUtil.getDecoderStream(inputStream1)

        val pgpPub = PGPPublicKeyRingCollection(inputStream1, calculator)

        var key: PGPPublicKey? = null

        val rIt = pgpPub.keyRings

        while (key == null && rIt.hasNext()) {
            val kRing = rIt.next()
            val kIt = kRing.publicKeys
            while (key == null && kIt.hasNext()) {
                val k = kIt.next()

                if (k.isEncryptionKey) {
                    key = k
                }
            }
        }

        requireNotNull(key) { "Can't find encryption key inputStream key ring." }

        return key!!
    }

    private fun readPrivateKey(inputStream: InputStream): PGPSecretKey {
        var inputStream1 = inputStream
        inputStream1 = PGPUtil.getDecoderStream(inputStream1)
        return requireNotNull(KeyRingReader.readSecretKeyRing(inputStream1).secretKey)
    }

    @Throws(Exception::class)
    fun decrypt(inputStream: InputStream, output: OutputStream, privateKey: String?, password: String?, fileLength: Long, publicKey: List<String>?) {
        lastVerifyResult = true
        this.progress?.stop = true
        val progress = Progress()
        this.progress = progress
        progress.total = fileLength
        var decryptionStream: DecryptionStream? = null
        try {

            decryptionStream = DecryptionBuilder()
                    .onInputStream(inputStream)
                    .let {
                        if (privateKey != null && password != null) {
                            val settings = KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.MD5, 0)
                            val secretKeys = KeyRingReader().secretKeyRing(privateKey)
                            val secretKeyDecryptor = PasswordBasedSecretKeyRingProtector(settings, SecretKeyPassphraseProvider { Passphrase(password.toCharArray()) })
                            it.decryptWith(
                                    secretKeyDecryptor,
                                    BCUtil.keyRingsToKeyRingCollection(secretKeys)
                            )
                        } else {
                            it.doNotDecrypt()
                        }
                    }
                    .let { builder ->
                        val publicKeyRings = publicKey?.map { key ->
                            KeyRingReader.readPublicKeyRing(ByteArrayInputStream(key.toByteArray()))
                        } ?: listOf()
                        val pgpPub = PGPPublicKeyRingCollection(publicKeyRings)
                        builder
                                .verifyWith(pgpPub)
                                .handleMissingPublicKeysWith {
                                    lastVerifyResult = false
                                    null
                                }
                    }
                    .build()


            val byffer = ByteArray(4096)
            var length: Int
            while (true) {
                length = decryptionStream.read(byffer)
                if (length <= 0) {
                    break
                }
                progress.update(length)
                output.write(byffer, 0, length)
            }
        } catch (e: Throwable) {
            throw  e
        } finally {
            decryptionStream?.close()
            output.close()
            inputStream.close()
            progress.complete = true
        }
    }

    @Throws(IOException::class, NoSuchProviderException::class, PGPException::class)
    fun encrypt(
            output: OutputStream,
            input: InputStream,
            publicKeys: List<String>?,
            privateKey: String?,
            password: String?,
            fileLength: Long
    ) {

        this.progress?.stop = true
        val progress = Progress()
        this.progress = progress
        progress.total = fileLength

        var encryptionStream: EncryptionStream? = null
        try {

            encryptionStream = EncryptionBuilder()
                    .onOutputStream(output)
                    .let {
                        if (publicKeys != null) {
                            val encKey = publicKeys.map { key ->
                                readPublicKey(ByteArrayInputStream(key.toByteArray()))
                            }

                            it.toRecipients(*encKey.toTypedArray())
                                    .usingAlgorithms(
                                            SymmetricKeyAlgorithm.AES_256,
                                            HashAlgorithm.SHA512,
                                            CompressionAlgorithm.ZIP
                                    )
                        } else {
                            it.doNotEncrypt()
                        }
                    }
                    .let {
                        if (privateKey == null || password == null) {
                            it.doNotSign()
                        } else {
                            val settings = KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.MD5, 0)
                            val secretKeys = KeyRingReader().secretKeyRing(privateKey).secretKeys
                            var signingKey: PGPSecretKey? = null
                            secretKeys.forEach { key ->
                                if (key.isMasterKey || signingKey == null) {
                                    signingKey = key
                                }
                            }
                            if (signingKey == null) {
                                return@let it.doNotSign()
                            }
                            val secretKeyDecryptor = PasswordBasedSecretKeyRingProtector(settings, SecretKeyPassphraseProvider { Passphrase(password.toCharArray()) })

                            it.signWith<Any>(secretKeyDecryptor, signingKey)
                        }
                    }
                    .asciiArmor()

            val byffer = ByteArray(4096)
            var length: Int
            while (true) {
                length = input.read(byffer)
                if (length <= 0) {
                    break
                }
                progress.update(length)
                encryptionStream.write(byffer, 0, length)
            }

        } catch (e: Throwable) {
            if (e is PGPException) {
                throw InputDataError()
            } else {
                e.printStackTrace()
                throw e
            }
        } finally {
            encryptionStream?.close()
            input.close()
            output.close()
            progress.complete = true
        }
    }

    fun getEmailFromKey(inputStream: InputStream): KeyDescription {
        var userIDs: Iterator<String>
        var bitStrength: Int
        var isPrivate: Boolean
        try {
            val key = readPublicKey(inputStream)
            userIDs = key.userIDs
            bitStrength = key.bitStrength
            isPrivate = false
        } catch (e: PGPException) {
            inputStream.reset()
            val key = readPrivateKey(inputStream)
            userIDs = key.userIDs
            bitStrength = key.publicKey.bitStrength
            isPrivate = true
        }
        val users = ArrayList<String>()
        while (userIDs.hasNext())
            users.add(userIDs.next())
        return KeyDescription(users, bitStrength, isPrivate)
    }

    fun createKeys(length: Int, email: String, password: String): List<ByteArray> {
        val rsaLength = when {
            length <= 1024 -> RsaLength._1024
            length <= 2048 -> RsaLength._2048
            length <= 3072 -> RsaLength._3072
            length <= 4096 -> RsaLength._4096
            else -> RsaLength._8192
        }

        val keyRing = PGPainless.generateKeyRing().withMasterKey(
                org.pgpainless.key.generation.KeySpec.getBuilder(RSA_GENERAL.withLength(rsaLength))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withPrimaryUserId(email)
                .withPassphrase(Passphrase(password.toCharArray()))
                .build()
        val secretOut = ByteArrayOutputStream()
        val publicOut = ByteArrayOutputStream()
        val armoredSecretOut = ArmoredOutputStream(secretOut)
        val armoredPublicOut = ArmoredOutputStream(publicOut)
        armoredSecretOut.write(keyRing.secretKeys!!.encoded)
        armoredSecretOut.close()
        armoredPublicOut.write(keyRing.publicKeys!!.encoded)
        armoredPublicOut.close()

        return arrayListOf<ByteArray>(publicOut.toByteArray(), secretOut.toByteArray())
    }


    fun symmetricallyEncrypt(inputStream: InputStream,
                             outputStream: OutputStream,
                             prepareEncrypt: File,
                             fileLength: Long,
                             password: String) {
        this.progress?.stop = true
        val progress = Progress()
        this.progress = progress
        progress.total = fileLength
        var preparedInputStream: InputStream? = null
        var encOut: OutputStream? = null
        var out = ArmoredOutputStream(outputStream);
        try {
            val encryptionAlgorithm = SymmetricKeyAlgorithm.AES_256
            val compressionAlgorithm = CompressionAlgorithm.ZIP
            val passphrase = Passphrase(password.toCharArray())
            compress(inputStream, FileOutputStream(prepareEncrypt), compressionAlgorithm.algorithmId, fileLength)
            preparedInputStream = FileInputStream(prepareEncrypt)

            val encGen = PGPEncryptedDataGenerator(
                    JcePGPDataEncryptorBuilder(encryptionAlgorithm.algorithmId)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(SecureRandom())

            )
            //BcPBEKeyEncryptionMethodGenerator
            //JcePBEKeyEncryptionMethodGenerator
            encGen.addMethod(
                    BcPBEKeyEncryptionMethodGenerator(passphrase.chars)
                            .setSecureRandom(SecureRandom())
            )

            encOut = encGen.open(out, prepareEncrypt.length())!!


            val byffer = ByteArray(4096)
            var length: Int
            while (true) {
                length = preparedInputStream.read(byffer)
                if (length <= 0) {
                    break
                }
                progress.update(length)
                encOut.write(byffer, 0, length)
            }
            encOut.close()
        } catch (e: Throwable) {
            throw  e
        } finally {
            prepareEncrypt.delete()
            encOut?.close()
            preparedInputStream?.close()
            inputStream.close()
            out.close()
            outputStream.close()
            progress.complete = true
        }
    }

    @Throws(IOException::class, PGPException::class)
    fun symmetricallyDecrypt(inputStream: InputStream, outputStream: OutputStream, password: String) {
        this.progress?.stop = true
        val progress = Progress()
        this.progress = progress
        val passphrase = Passphrase(password.toCharArray())
        val pbe: PGPPBEEncryptedData

        val decoderInput = PGPUtil.getDecoderStream(
                inputStream
        )

        try {
            val pgpF = BcPGPObjectFactory(decoderInput)
            val enc: PGPEncryptedDataList
            var o = pgpF.nextObject()

            enc = if (o !is PGPEncryptedDataList) {
                pgpF.nextObject() as PGPEncryptedDataList
            } else {
                o
            }

            pbe = enc.get(0) as PGPPBEEncryptedData

            val clear = pbe.getDataStream(
                    BcPBEDataDecryptorFactory(passphrase.chars, digestCalculator))

            var pgpFact = BcPGPObjectFactory(clear)

            o = pgpFact.nextObject()
            if (o is PGPCompressedData) {
                pgpFact = BcPGPObjectFactory(o.dataStream)
                o = pgpFact.nextObject()
            }

            val ld = o as PGPLiteralData
            val unc = ld.inputStream


            val byffer = ByteArray(4096)
            var length: Int
            while (true) {
                length = unc.read(byffer)
                if (length <= 0) {
                    break
                }
                progress.update(length)
                outputStream.write(byffer, 0, length)
            }


        } finally {
            outputStream.close()
            decoderInput.close()
            progress.complete = true
        }

        if (pbe.isIntegrityProtected) {
            if (!pbe.verify()) {
                throw PGPException("Integrity check failed.")
            }
        } else {
            throw PGPException("Symmetrically encrypted data is not integrity protected.")
        }
    }

    @Throws(IOException::class)
    private fun compress(inputStream: InputStream, outputStream: OutputStream, algorithm: Int, size: Long) {
        val comData = PGPCompressedDataGenerator(algorithm)
        val cos = comData.open(outputStream)

        val lData = PGPLiteralDataGenerator()

        val pOut = lData.open(cos,
                PGPLiteralData.BINARY,
                PGPLiteralDataGenerator.CONSOLE,
                size,
                Date()
        )
        Streams.pipeAll(inputStream, pOut)
        pOut.close()

        comData.close()
    }

    fun addSignature(text: String, privateKeyText: String, password: String): String {
        val inputStream = ByteArrayInputStream(text.toByteArray())
        val outputStream = ByteArrayOutputStream()
        val settings = KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.SHA512, 0)
        val secretKeys = KeyRingReader().secretKeyRing(privateKeyText)
        val secretKeyDecryptor = PasswordBasedSecretKeyRingProtector(settings, SecretKeyPassphraseProvider { Passphrase(password.toCharArray()) })
        var signingKey: PGPSecretKey? = null
        secretKeys.forEach { key ->
            if (key.isMasterKey || signingKey == null) {
                signingKey = key
            }
        }
        if (signingKey == null) {
            signingKey = secretKeys.secretKey
        }
        val privateKey = signingKey!!.extractPrivateKey(secretKeyDecryptor.getDecryptor(signingKey!!.keyID))
        val signatureAlgo = HashAlgorithmTags.SHA512

        val signatureGenerator = PGPSignatureGenerator(
                BcPGPContentSignerBuilder(privateKey.publicKeyPacket.algorithm, signatureAlgo))
        signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey)

        val armor = ArmoredOutputStream(outputStream)
        val stream = BCPGOutputStream(armor)

        val buff = ByteArray(1024)
        var read = inputStream.read(buff)
        while (read != -1) {
            signatureGenerator.update(buff, 0, read)
            read = inputStream.read(buff)
        }
        val pgpSignature = signatureGenerator.generate()

        pgpSignature.encode(stream)
        armor.close()
        stream.close()
        outputStream.close()
        val signature = outputStream.toByteArray()

        return PGP_SIGN_TITLE + "\r\n" +
                "Hash: SHA512\r\n\r\n" +
                text + "\r\n" +
                String(signature)
    }

    fun verifySignature(text: String, publicKeys: List<String>): String {

        lastVerifyResult = false

        val startMessage = text.indexOf(PGP_SIGN_TITLE)
                .let {
                    var index = text.indexOf("\n", startIndex = it + PGP_SIGN_TITLE.length) + 1
                    index = text.indexOf("\n", startIndex = index) + 1
                    text.indexOf("\n", startIndex = index) + 1
                }

        val startSignature = text.indexOf(BEGIN_SIGNATURE)

        val endData = text.substring(startMessage, startSignature).let { text ->
            text.lastIndexOf("\n").let {
                if (text[it - 1] == '\r') {
                    it - 1
                } else {
                    it
                }
            }
        } + startMessage

        if (startSignature < 0)
            return ""
        val endSignature = text.indexOf(END_SIGNATURE).let {
            if (it < 0)
                return ""
            it + END_SIGNATURE.length
        }
        val signedData = text.substring(startMessage, endData)
        val signedDataStream = ByteArrayInputStream(signedData.toByteArray())

        val signature = ByteArrayInputStream(text.substring(startSignature, endSignature).toByteArray())
        try {

            val decoderStream = PGPUtil.getDecoderStream(signature)
            val pgpPublicKeyRings = PGPPublicKeyRingCollection(publicKeys.map { KeyRingReader().publicKeyRing(it) })

            val pgpFact = JcaPGPObjectFactory(decoderStream)
            val sig = (pgpFact.nextObject() as PGPSignatureList).firstOrNull {
                pgpPublicKeyRings.contains(it.keyID)
            } ?: return signedData
            val key = pgpPublicKeyRings.getPublicKey(sig.keyID)
            sig.init(BcPGPContentVerifierBuilderProvider(), key)
            val buff = ByteArray(1024)
            var read = signedDataStream.read(buff)
            while (read != -1) {
                sig.update(buff, 0, read)
                read = signedDataStream.read(buff)
            }
            signedDataStream.close()

            lastVerifyResult = sig.verify()
            return signedData
        } catch (ex: Exception) {
            ex.printStackTrace()
            return signedData
        }

    }

    fun checkPassword(password: String, privateKey: String): Boolean {
        return try {
            val settings = KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.MD5, 0)
            val secretKeyRing = KeyRingReader().secretKeyRing(privateKey)
            val secretKeyRingProtector = PasswordBasedSecretKeyRingProtector(settings, SecretKeyPassphraseProvider { Passphrase(password.toCharArray()) })
            val keys = secretKeyRing.iterator()
            while (keys.hasNext()) {
                val key = keys.next()
                key.extractPrivateKey(secretKeyRingProtector.getDecryptor(key.keyID))
            }
            true
        } catch (e: Throwable) {
            false
        }
    }

    fun extractPublic(privateKey: String): String {
        val secretKey = readPrivateKey(ByteArrayInputStream(privateKey.toByteArray()))
        val out = ByteArrayOutputStream()
        val armored = ArmoredOutputStream(out)
        secretKey.publicKey.encode(armored);
        armored.close()
        out.close()
        return out.toByteArray().toString(Charsets.UTF_8)
    }


    companion object {
        private const val PGP_SIGN_TITLE = "-----BEGIN PGP SIGNED MESSAGE-----"
        private const val BEGIN_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"
        private const val END_SIGNATURE = "-----END PGP SIGNATURE-----"
    }
}
