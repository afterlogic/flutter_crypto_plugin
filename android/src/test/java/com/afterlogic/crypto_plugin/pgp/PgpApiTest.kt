package com.afterlogic.crypto_plugin.pgp

import org.junit.Test
import org.pgpainless.key.parsing.KeyRingReader
import java.io.File

class PgpApiTest {

    @Test
    fun testFile() {
        val file = File(testFile)
        assert(file.exists()) { "past you test file in 'testFile'" }
        assert(file.canRead()) { "cant read file" }
        assert(file.canWrite()) { "cant write file" }
    }

    @Test
    fun testGetUserUid() {
        val pgpHelper = PgpApi()
        val keys = pgpHelper.createKeys(2000, "test@afterlogic.com", "111")
        var result = pgpHelper.getKeyDescription(keys.first())
        assert(result.emails.size == 1 && result.emails[0] == "test@afterlogic.com")
        result = pgpHelper.getKeyDescription(keys[1])
        assert(result.emails.size == 1 && result.emails[0] == "test@afterlogic.com")
    }

    @Test
    fun testGenerateKey() {
        val pgpHelper = PgpApi()
        var keys = pgpHelper.createKeys(2000, "test@afterlogic.com", "111")
        pgpHelper.setPrivateKey(keys[1])
        pgpHelper.setPublicKeys(listOf(keys[0]))

        val message = "message".toByteArray()
        val messageD = pgpHelper.encryptBytes(message, null)
        val messageE = pgpHelper.decryptBytes(messageD, password)
        assert(String(messageE) == String(message))

        keys = pgpHelper.createKeys(4000, "test@afterlogic.com", "111")
        val description = pgpHelper.getKeyDescription(keys.first())
        assert(description.length == 4096)
    }

    @Test
    fun testPgpApi() {
        val pgpHelper = PgpApi()
        pgpHelper.setPrivateKey(privateKey)
        pgpHelper.setPublicKeys(listOf(publicKey))

        val message = "message".toByteArray()
        val messageEncrypted = pgpHelper.encryptBytes(message, null)
        val messageDecrypted = pgpHelper.decryptBytes(messageEncrypted, password)
        assert(String(messageDecrypted) == String(message))
    }


    @Test
    fun testFilePgpApi() {
        val pgpHelper = PgpApi()
        val startLength = File(testFile).length()

        pgpHelper.setPrivateKey(privateKey)
        pgpHelper.setPublicKeys(listOf(publicKey))

        pgpHelper.encriptFile(testFile, testEncrypt, null)
        pgpHelper.decryptFile(testEncrypt, testFile, password)
        assert(startLength == File(testFile).length())
    }

    @Test
    fun testSignPgpApi() {
        val pgpHelper = PgpApi()

        val message = "message".toByteArray()

        pgpHelper.setPublicKeys(listOf(publicKey))
        pgpHelper.setPrivateKey(privateKey)

        var messageEncrypted = pgpHelper.encryptBytes(message, password)
        var messageDecrypted = pgpHelper.decryptBytes(messageEncrypted, password)
        assert(pgpHelper.verifyResult() == true)
        assert(String(messageDecrypted) == String(message))

        messageEncrypted = pgpHelper.encryptBytes(message, password)
        pgpHelper.setPublicKeys(null)
        pgpHelper.decryptBytes(messageEncrypted, password)
        assert(pgpHelper.verifyResult() == false)

        messageEncrypted = pgpHelper.encryptBytes(message, password)
        pgpHelper.setPublicKeys(listOf(otherPublicKey))
        pgpHelper.decryptBytes(messageEncrypted, password)
        assert(pgpHelper.verifyResult() == false)

        pgpHelper.setPublicKeys(listOf(publicKey))
    }

    @Test
    fun testPrimarySign() {
        val message = "message asd adasdasd"
        val pgp = Pgp()
        val signed = pgp.addSignature(message, privateKey, password)


        var verify = pgp.verifySignature(signed, listOf(otherPublicKey))
        assert(pgp.lastVerifyResult == false)
        assert(verify == message)
        verify = pgp.verifySignature(signed, listOf(publicKey))
        assert(pgp.lastVerifyResult == true)
        assert(verify == message)
    }

    @Test
    fun testSymmetric() {
        val pgpHelper = PgpApi()
        val decrypt = File(testFile)
        val encrypt = File(testEncrypt)

        val startLength = decrypt.length()
        pgpHelper.setTempFile(temp)

        pgpHelper.encryptSymmetricFile(decrypt.path, encrypt.path, password)
        pgpHelper.decryptSymmetricFile(encrypt.path, decrypt.path, password)
        assert(startLength == decrypt.length())

        val message = "message!";
        val encrypted = pgpHelper.encryptSymmetricBytes(message.toByteArray(), password)
        val decrypted = pgpHelper.decryptSymmetricBytes(encrypted, password)
        assert(decrypted.toString(Charsets.UTF_8) == message)
    }

    @Test
    fun testPassword() {
        val pgp = PgpApi()
        assert(pgp.checkPassword(password, privateKey))
        assert(!pgp.checkPassword(password + 1, privateKey))
    }

    @Test
    fun test() {
        val pgp = Pgp()
        val verify = pgp.verifySignature(testMessage, listOf(testKey))
        assert(pgp.lastVerifyResult == true)
        verify
    }

    @Test
    fun extractPublicKey() {
        val pgp = PgpApi()
        val pair = pgp.createKeys(2000, "test@mail.com", "111")
        val extracted = pgp.extractPublic(pair.last())
        assert(extracted == pair.first())
    }

    @Test
    fun testKeyInfo() {
        testPrivateKeys.forEach {
            val secretKeyRing = KeyRingReader().secretKeyRing(it)
            print("\n")
            secretKeyRing.publicKey.userIDs.forEach {
                print("$it\n")
            }
            secretKeyRing.secretKeys.forEach {
                print("id = ${it.keyID}\nisSigningKey = ${it.isSigningKey}\nisMasterKey= ${it.isMasterKey}\n")
            }
        }
    }

    companion object {
        // past you test file
        const val testFile = "D:\\file.txt"


        const val testEncrypt = "$testFile.gpg"
        const val temp = "$testFile.temp"
        const val password = "111"
        const val privateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: OpenPGP.js v4.5.5\nComment: https://openpgpjs.org\n\n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\nkiDE\n=JfKa\n-----END PGP PRIVATE KEY BLOCK-----"
        const val publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js v4.5.5\nComment: https://openpgpjs.org\n\nxsBNBF2bSLIBCACQPD0/sROI7sdCtDxC21CLZPBM9ZBJAsqpOjuL8yYyuzyO\nypr+eS+XyI3yggq6G/fQHvY7zrDXTz+Nlr0lU7wYr93pKzbjNgmhQjWSKN47\nn20h1vXM9GIUeXlTrQB+Bv/xfGawHaWAwo5RpEB9vk8EYYzAPy8GCVCPcpYw\nO8civ6IYSdDur+yymPcc07OCSIslsIG3sG+B1N4zTcQATZLCC5QD2KZO8kDJ\nsbl3haz+IJjIsnwGHyahagpHM1YvLpsb5Bkehs7zTgmM+NEeAjLaFCsN28Vd\nMre7jxbpCP0ZSXbyn8DYWuYo8iJ19QplqRBNogpeet5Yttv0Jif9lT09ABEB\nAAHNGlRlc3QgPHRlc3RAYWZ0ZXJsb2dpYy5jb20+wsB1BBABCAAfBQJdm0iy\nBgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIeAQAKCRCdhr39jokMLo1QB/9t2DEI\nEOkCgTxeDUEQfHzTfzoCnBXV7uXqQw1aqRdEW7zCCKnAR1+NxoGIa4dsd4H/\nYuNHrh9B0Uh3ywE4Y8e4JDHfj9g1G27FAHbW6VAlgeDc0qt1GFX9ib9Z+fk1\nbxfNwyBj0h4iZXlxQslMIMJqw1IcLWB0cN3xjzKTUHaNV9zd8hAUp4Tqru4B\n6rb1Xzg61RAsg4Ks+jacfzIc3lr05yGBaVn3dkcn5pKL46sPBBb3eawe5NoG\nKgoTe616y0mn6SzMU/1NG+Ul3L8lR8fi90a6zy0UIBbhWGtj8+RfLjmdKVcu\nYYz9ij6kX3PmVDK47ABA3/qFqusKmw+bate8zsBNBF2bSLIBCADXOrcU44W5\nodCPeYbxGqB5pFj4fqWnMi6vzv4DWl+Tb7gu3fneL8/pwM/0l0cMyIEZJThc\nEJ2pF8zk+hV6cwTrNTgO+VCMOcedzlJ43T5dsPtlIec3NQT573d/HE3DL7kK\nAdLOZTlJ/N26RVvluM9za1IDkhKzxCHNNK3Y+AfmgKfKu3VB4jnYVX2B9R0D\nhUOMKfVQV4uBvxTqxVWVEyu+s6EJCDufk9dVSDmbUu0dtOEprtPCqy2bU7Y9\nBvVeAakiExRF0I0QuT43JShv7iuGQYOpR0TqJCTLbXSHaWngkVsOw3PilDYa\n0v+3w8O60XEvxHFLX7x6g47tBbfkrUHzABEBAAHCwF8EGAEIAAkFAl2bSLIC\nGwwACgkQnYa9/Y6JDC7d2Qf/dIgQqcliWOkuldsfIZ+O4pufBGX4BWsb+x4O\nd2ccnt13s22190wkfq/fjd0Rfhpn/OUaL3HLjE+f/nXq6MUvWpx2ISO90AAy\nGXITp2b80Dna3GOaEJRJ1sfXQ8+i0F0iRPHSESieYL5FDoDIdo5PtJwiEysM\nU3+DR9oHgFBgd8b6LtZsgzEj5VXC7r0WJX4EaNVY9be2kO2sJIr5vJukntkj\nWRwqXezF9HKanu7vZGL6JhYpcEL9SiDxCVdZ+I6bL+zQM5+DxjfjvLpctGl3\nYNeUf2hCfeJq0+X9liefXQUwYmm2kkmuNq1zM/ZwiRz9s+yRnrBWEa1ez+lK\nLJIgxA==\n=c5ef\n-----END PGP PUBLIC KEY BLOCK-----"
        const val otherPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js v4.5.5\nComment: https://openpgpjs.org\n\nxsBNBF4HLmMBCADXOGziqvmTsyaGTusg3RO9uRGAXOHRivnzhdfr+F3VSRPW\nKsHoYQV5jMMmlvo4xSQx3GJvCJkvyT7qcD2UzansuIT2eKhfeIk8tQkpFZsT\nLoTvBIhoQPKfaTPDW8VkH7lm5uRdm+pNN/4ZHsAExrUfatX8dRshY60pta8z\nGHbLvG7hA6yWMVDNe2ICS9TbJX2RUHJHADflVBMNFqZ0tlKWcwGdo1mDEyJa\nnP9anHN9YMlUDf2SsTN6Lywla9rLaAo9bdFhI5oPO5g9ThsIgzKrOwCAWXpD\nhPZHWTc/S13RdAtqbTct8rVO2C+QDDmL9Zsk2V2vQPsXyPAgPBkCnqZrABEB\nAAHNIVRlc3RlciBOYW1lIDx0ZXN0QHByaXZhdGVtYWlsLnR2PsLAdQQQAQgA\nHwUCXgcuYwYLCQcIAwIEFQgKAgMWAgECGQECGwMCHgEACgkQo7ON4jvucn2J\nGgf8D8svo9LoG+m71ngVJqVP9Ghru4oU5NkpygK860ER6sonF0if8wh0ZTVh\nmNrCt75BBqkhv6z3dqTUDyIshsjQv7q5QOePv+LgniXENZm8oZ2UiejJCEJt\ntxoTYThXBQFQ62FOe8g2T8wDHyYFi/4dCTD0C40nuD3a3dLzE5egR3OapohN\nViFeXuPcPEQQMpDI45tgg+38kuFUAlvHHuKEZiK7EGFYrJyy5cpvADPRRLaT\nymNw6x3HNQmOKFLs6H+hxx3dBBrSpbywA6CbxIZi5WU8arv+uoVnawoYkK91\nM+/6JvWERxsnntQzh4/hmygdbNdVDDnlg3TzxfbmzZzBA87ATQReBy5jAQgA\nscIlHpi2ae/EUM26G7p7YtyWBoU15jH38m2D4irrIO+gppwsUiUfqdq8/ZwX\nzj1batozFDBOyGjNl1Yid+RJcWgyyF8Ta8GryUCuFkQ+wXbIN6Y4BRcw5gvB\n2Eu9rNWiXnSJ7h4z5X48hSwX9v7RiDY8oq/nqM5UD0a741QkVuJUqyv8BoU7\n2CdsP0nw4SiMjUuOO0XLWr7WtRzNZAmYA4kmHaoRMJzDB7tU32XW9Q8DD0Z3\nwu2ug/9Mt2whmngoQ8BCbmd3S4l0yzMAHe5KOiR89GRMNlIjas5LNZIsBBUk\nphdBwv3OkeHW8Iqpb5567wvoQWpZQOWQZw7nje4nDQARAQABwsBfBBgBCAAJ\nBQJeBy5jAhsMAAoJEKOzjeI77nJ94BsH/RPH78amCkyCBioE/39EsJldUyrw\nZOh0Hhlwrkkjz7opo/quP45L3Bg100RC/k+L+6aI768uQ+MrjtASkEjX8drw\nsMir8eKWv+87LX5r5lMz2iougMPiQPoUlxuWyuiZyV9GV5llwPjzx2loGuH9\nOip59u2gAnEE1Gc+fY3NE4WQ9Wf/LzoPBo3aZ6vDV4rVSxRMPXpIfI8mdygO\n8zB/Dxs6/eeH7ntZFcvLT24z6yxzh4LVzbs/QQR22+YRkixnWt2UPHoUzSur\niplhyDtyd6SVyhLKSI3U3QGU1wc/spRiaCbEb9THkKHB9Ys815FtO8xJc4uF\nJ3I8V7VaXTuUvhU=\n=Gg6L\n-----END PGP PUBLIC KEY BLOCK-----"
    }

    val testKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Generated by DMSOpenPGP\n" +
            "\n" +
            "mQGNBF5KZcIBDAClTKnlrd545OMuJ/qmcy00XZDRJYfG7qiK5qJHJv8tNoTU2cz9\n" +
            "bP2AkySFyAF4Xi6auKOv1SKMzAFxXfJ1IH1VXoJrFQOn+gAFWjZZGqNxxQJN1BVa\n" +
            "BY6g3M9L5a2fjHxa+poVrG50PfeLGJwOhWxuoth9A44IyrRjllfqXLOyNN6smYt7\n" +
            "wDj86g+uYgnaV9qSE99IHreR37wfLUE9QNN0tM2cswIpE4JJWkYOEhL5lJvNCW0W\n" +
            "NcSgXD/sOjI46CxZfs7NRPeP2hCgvycIg2F7ksGcXiHbLJD0F7/ejs/GTYGyGbhg\n" +
            "iQhZaXci6NenHR9tSOXak0Wub3plSG5oFWCfb5XmbcYJFXnMEwSQkh0NJZTUu9JC\n" +
            "4auxrvDH8u6Z3HPOAO+sAr2bq20s0VYPSJMubPVK7JuciH/nI0sSm3EBWygPTqbt\n" +
            "6ilMSQfCOPLDTD9YoxxVk8V05teGr9p20qfFmFENPDr/zdXhFfilVfRfLC9Cz/XD\n" +
            "u7WI/gjoPYRXw9MAEQEAAbQaVGVzdCA8dGVzdEBhZnRlcmxvZ2ljLmNvbT6JAa4E\n" +
            "EwEKABgFAl5KZcMCGwMECwkIBwYVCAIJCgsCHgEACgkQfNaRNO21bChWEAv/cUGR\n" +
            "63V3binH9k6XZdYscJjVBgcDdFfQtx1Xx/EsvB2za57uTkUBh9+ZGx5vUyU/UGv5\n" +
            "f3FZ+Z5xVGToT0K2VOjc4AqBHhdKbZze/QX2k8+krYUKHpvFk2TA3WiZAeAKpD49\n" +
            "rGPF+uWIQdqUs9tEiQdtXLe6H37OCdYPYMT/7BNea6YvdsxQdgwO3sD+S/aimaqn\n" +
            "ZowIpIvOXIuq4wqaOhzkajp8FMeAWntWFJFxJ24pteg+CiOUp5nWFDbTwF4UolkK\n" +
            "1qolOXpoP8kSjyCNP5sHZWnfJczpIiGNoOIAAWgG8PsL4e7PhlrbhywLznKv3jmm\n" +
            "JwC+d5PvdayJqIR92NsM+lX6u5CWKqmQm0vPWVYato1rpy8KUFqFUy6DuWZNp+Lk\n" +
            "UeM2ar8m0z8FS7Jyi5kXctrNNoNtt2hVYrwaSZ60312E1l404ReNVK3KdY6DRDeP\n" +
            "rfrElRBy+C4xhzqQZ9jtx5I1peuQemyeXOtRk8WgWE4k5tGp87kUVwE2g/ocuQGN\n" +
            "BF5KZcIBDAC4CqdFy9qWLietwi+O6vHZ8B1pw/+pMidW5MP4cLf0lkO1ZSwC3B9e\n" +
            "Q1pjZ3rjhGM0V0Vz5uEA+Ik9O8NtTBnjC7TvvkJ757Rqa22aDXj0NMxB9xmXfzDf\n" +
            "J+nvIm1tm7vF+HustJknXKpF0KdaLlBHxAmUcyD4EYEyfYe/M3v5ToDz2kqAuXVf\n" +
            "rIy5XqsBBy9NK6ss307bf4Q2nosFfDHcLiDjn3iTiVxpfnEUPBJSNHmqhpus68NU\n" +
            "SC7lZciq1w3Wia4XOO84QyOZib0QEzH3pJGy8R/os355Li7Kq/MTidQqDYw2I97L\n" +
            "kiOR07imlM6UFZ4ExdL0FRlU4ZiQt4Dp1Wb3MAL+y+KHjEJhWE2zRjzJJxrMBtgZ\n" +
            "O7m0clpElMkL3vB/Ckl4gcB5ck8aU15jX4cWItj7njm7MO60/ceKwGf6zRU3RiLC\n" +
            "AOQm77nSiPvNeIRWQXvMUoERaEVi/xtXsNNbWu64Iuj9F3e1nWO/pPOqorUH/ye+\n" +
            "XO3zEFFJ8nUAEQEAAYkBnwQYAQoACQUCXkplwwIbDAAKCRB81pE07bVsKGHPC/43\n" +
            "8+qGaMrvvifg2/y4mI0tDX941EJSjWkFTBRGXm1ebWHt6cKJQq7zJFkS0BtTAwZk\n" +
            "hYWXDBWYJ4upLGbUYXxJIGUkCmX+OMz9Szpc3QAVeN/tWM4RCU1O0jWkHX1fk6kh\n" +
            "KhtsBQFe1ZgxZQKGzKmfqq70yt3XuXPgxBqXsnZmoydCnn5N4wiDyfsMOja6F3B4\n" +
            "ZEZfCecqmF71rgczdA+78w9EXG/LIvthioJiQQhzrr1DRNWilwUorR+3FtYwLQmo\n" +
            "LJVUH8JjXxhKi1J3uVjJvaR5PlxwNtCPKxrOqdxZgUv3+LupzuX5Delw8zLs+Jlx\n" +
            "f1qsDjastimY1OC5G4vovg6KsgkSgA6rCVD/0oo3U+xqBldXm/c+9DEiZ7wqtFsX\n" +
            "SPYUJw7v23i8yVgb39s0qtU7kKXANhNoM54AtVZMlZxHFEqBagkIOs01HehAj/KD\n" +
            "akvAopKOH1KX7HB6BXhR/1JDIuFrvorDcqsU6L0GZp/a5cOtRefjSVgD9OcINiE=\n" +
            "=IQFl\n" +
            "-----END PGP PUBLIC KEY BLOCK-----"
    val testMessage = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA512\n" +
            "\n" +
            "Test\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Comment: Encrypted by DMSOpenPGP\n" +
            "\n" +
            "iQG4BAABCgAiGxxUZXN0IDx0ZXN0QGFmdGVybG9naWMuY29tPgUCXkpnQQAKCRB8\n" +
            "1pE07bVsKGiSC/sEOMLlWiRXWpRZQ6q/vd7U6roFmVYVPSdQ1KoSvrkiSlv3TF9d\n" +
            "LuUC1mbZjhh37XAshbKLxU5QWYM2roH3lnMjD6j1s2IiV5IrFhQqXkckgq1jyWw+\n" +
            "Za+KGOYZqL32jOxpjgefVWXgmAw+575rTkh+s5NcTyfWRjZU5TZ4Oe8bfB+vsZ/I\n" +
            "MkQ8DosfxTg2+Mot/vy0g9q8aHboIUhRcGhJYo26ZMIOUxrHgkav8oByArehUu+b\n" +
            "08zWJA04H/7igZ1pjJd8eWWChxd7ccf1aKZOqOlPMi5Dim+R5F1rF/Y6JQpi9f28\n" +
            "THuw81w1/Qt0v5Au/RMVzhGJhe54eCpAFShY/+7EIHIH8DQ8m5UpKGJlOfysocje\n" +
            "IKYfBju+AQjSSo3p0cfUOODaXdnbeJ+Enndobp930gG/nf5sFxe9h+xwsVOCquRM\n" +
            "L5KvrrTFz0zIXWDJvWumVaq2D8T5xVhnu66E7FaHGsvaVrv9ZlQDGyeB4YtQLDQn\n" +
            "IdCur0X2/Gh8m0g=\n" +
            "=TCEa\n" +
            "-----END PGP SIGNATURE-----\n" +
            "\n" +
            "Sent with PrivateMail"

    val testPrivateKeys = arrayListOf<String>("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Generated by DMSOpenPGP\n" +
            "\n" +
            "lQWGBF4qt7sBDADQi8om7zEJZvy4Ng/kn2u6NKe262xPj1tpktCZ0/5K6eeC1Gp9\n" +
            "dwxG4BTIBQNaTiRr3w6gNZLGk04/T8Hlwv0h+RdYQVKreD8gj5/Rexuxv68MdU1u\n" +
            "mgHwqZNmsa8Hris2oVBkV5opBJbO7xnQxnk8rcwbWljcbSNgam0cnqBr+oMlXwz+\n" +
            "RjoNfTfAQtSczZhYW5y/3/MjGPZu0vwkVbbf9jDYctk0FfKbtuzqNTusCeBi9GAk\n" +
            "clwMPU68T5oz8Cw5B+rLxoDjp6pQTgGbWpqKwj8ewvRVifPXndvbV+RGQqoxy+vX\n" +
            "0Ir9TgejhyPrSL+MV6XMn/GHVbCpFtbDQ1dOzOhL2XKU6tvVXh1y9315T8Cux8OJ\n" +
            "5o4P7gOcll75BJi/zYKHjYC26DF1hIKBC9AAXLdm5xcwvEyk73ojTX+Y2vQNGj0y\n" +
            "yeyUZ5i7M2QhxqO0N9I/VmeFCIYdro5Xsz6znWHwZpu7xs54hBadIVr7iWusfyGv\n" +
            "h+eEe8NKRyCIgd8AEQEAAf4JAwi+98IBqmXBWZAGWcDwOilLA9IrGR5WdDRFsYot\n" +
            "XuGlIP74p6NHqh0Fkr0oD/nrlCiEFWZ2SzvJiI+mHOzrON/JgMaA1jeERwos9J47\n" +
            "IJLNJhJJTZEb8WXXWUY/poJNOX8zitoMHr3FJ9WPgHvFRrD2/7aYCjl0ShxNg9zn\n" +
            "kqJzSpE2UkMYSUt/f3ihbgl00Tph5UX17UnNKDxx8BSwYWeyZfvc0cz+qOvL+0yf\n" +
            "ElrURYRFQWGCz0Rj+Wx4CgqGJ9fhTUBcFucY+1XVUc1eU71MSkW3z51R54fmGUhK\n" +
            "oLpBo+A3axCwfjqFQt8YlnAS632OaGQXDJlgVWbGAJaA7obKnw8L+3m2I2cgKXPL\n" +
            "sFRrWszCdgd2IBi8zy7qFhceg7DYv4bswwIr05vbMAnKklSk3Jj3JCPkKjFj3NYo\n" +
            "PMd0lRRTwqO/Y5M1JVn9srn/YhYr/57/JioAmgp/gVtUgpmNqLY7o/HqHFJjfcvN\n" +
            "+qZB0M63rZWvg3H+n9HkEWmsMgQMsH/ccwVPQWY0HavbCga2gpsZD9sPmMdmsmXq\n" +
            "P8fTHsBx640sRpUUzjk18nPM0a4uvd8YT4Oc0KPVdLDPQnm2p18JLkdwUXWN0cFz\n" +
            "snowpApgK7qoPgoqFTCftyXKNiDZz4LqAyU4eV25sbHLD8k25gK5CIAwfxjWI68z\n" +
            "QtS3Cpa6cPFowmbJLHb6gSBSbKvexBHXv277YEFCivzwAX+rf3SjiIsVL3YGGy1+\n" +
            "rl440UrYw2r/AsfQcusIv3MQKjw/E4/bXuhzTue/6s2t9kOMjQDfBTH9BLm4OG4U\n" +
            "8oiRMRU4voRRYAScax/tAk4ds8EnQTax9Cw3egli5pk9nmrFXffL7RLD5tbkHLyv\n" +
            "B/bGhtLzJRmyMOyn29wpw9taCR6E/fbIOVjOR4VTPrMNzHbX8ZDvengKQsxzKPZN\n" +
            "JVC+c3NQzf619KUzjZiqw+YY0LGM7s8kk4vkT3wrvOX9Kcu+QYX9YknjqxXG2p90\n" +
            "F+5l0gA/dr8U9byXZvRsLJJWqGKr88AQxYqIUYzeqXWlPxCFnMZ8EvghGEI960rG\n" +
            "uHRhUBisl6oeU/MDS++/SnAk+K7/Z5N/HbwhTb0bTczww3/nVzlm5+H9hvTEHbHU\n" +
            "woY9f3AOE6Ww2tnbF8LpJajJy1jtJOnR5tD4L6xwLg7KMChLtNNsr+2YN6Zbf3pz\n" +
            "2tnPrm32R2sqtab6GZu3bNIKOkBK8BOtnMRmIAS5s1fER0g4qiQQcspzwdODjtvy\n" +
            "2JN9bHFRMdUI5/Ye2Ro2KHN8TANfwoJjIYRjbZd4Jk6m4q2UUH61UOB2nJUx/Siv\n" +
            "R65Hcw49ShjI7DZN1Z1DMcXy1klhuPUqNrQhIDxnb29nbGVwbGF5dGVzdEBwcml2\n" +
            "YXRlbWFpbC5jb20+iQGuBBMBCgAYBQJeKre9AhsDBAsJCAcGFQgCCQoLAh4BAAoJ\n" +
            "EP0914kY+1oADOEMAMi2xixLL/KFTPqNZNovQjtHDTJCxtIoymze1gquM5WjmuMa\n" +
            "sn4BlOei5/WU/dgUoTQ0h9MKbEt+0jpQA89XIc6IBeiQaKu40eaRwzLB0BVgVCCd\n" +
            "PwrbexjPqio7eKJo1YCBL1eKA/RPREZ4qITCImaFisFeJOj2rzyUySg1O4YJW932\n" +
            "BnN7tm8SpFrqY1V5kyx3O9hYm+DG1LybCNr7pQlU8sOgqA6AdJgmiGyJGT+hlFg4\n" +
            "3ZH3oouSPhM5YNDPEKmb7QUDgBLPXsJlEhzZSxzo62Oy/ysSC5cCdtIVXrXXsmJG\n" +
            "hnLRteRzGEuUL4ct1C3y5aB23cmRAIFTjNGNvjnzPc7Kl+gs1apkHEcoW1zInvHs\n" +
            "9qx8ekMqEQO/VHb75uxJPP8lRGeV7L7rTnjXNaS/8FzxJ19SpcoGrgtUHjXudXwm\n" +
            "CcIkiZHwnuM+KT4AFrSVcAYVwru5NJ53qVJ7SBoTq0BtauV1TzGrkERHkbtBUsJf\n" +
            "wyGX81Z44Nx1o4G+b50FhgReKre7AQwAvLpI5TFP5MuoyEC4xd+W0kut52P83c+x\n" +
            "oRKcAjbv6xY4j+muo5JaPYQuYxNKv2qJdVvNYBc6BBFQuAQyjHA8t0FOU4YK8uOG\n" +
            "gO+I9U7Bd6FK9GW2eYY0Gf+XcGPGUNfyUT+j2d6gr6+mjbri0aeiqMp2iSWd17a0\n" +
            "Sj/05oXXsUfv8kXvYBgrU/9FAkr9W+x7AQ6EIGMpTctCcWFq7d9o1o9Ih5apCpue\n" +
            "N6MLlSiyAVPJYIBM3ypG8b8J8+6SMGZGEJc8apyvV2/Cli/n67A3DdKg9VmbeY9R\n" +
            "no/87gPtdBWBQwIS/YSAPB89rDF907A3/bZt1qihc+ZK4voCyDiSeHsvkmDkLhKk\n" +
            "S796o8PTrKn292uE/6SJm4Q20XhtTujNGIRsyK90Vj6aOf82wTYNqu4DLcxeDiCU\n" +
            "HM8z7cNgi6aTn2DXffldVypGl3Yoje95z1gXStFP/hSv5MqjvcKcpAEP9XE/QiSu\n" +
            "KE8KbaTJlvoNYMn0+SO7Bos+svhUB8IJABEBAAH+CQMIvvfCAaplwVmQ+teC+KI+\n" +
            "xc5vwhBTDKYWQYZPxfTiv4uoL3YIHdJaU0sDHKfZYSY2N5RawKjiypsS87nRD3Bi\n" +
            "ZSafNp/DfTenM1UtdJ09O/MXqPczk0QcFSuOt/9sNVnMtpzqr4N3BxeuYKf+yyzp\n" +
            "Kr7dcR6B1zR+kb3BhHrm0OZany9/hNvxczrEaKfGaLrQoxehS7UlNHnOC81n2LJj\n" +
            "xDJWqopylkkIaLvttHE7fBfWpdsr6nb/4R90aTkBD/bYWc46UpoS2eOZol0Cg5b9\n" +
            "KKCzdZ5F7+T2R8aPGHRpLZTMKqH3kZXVRbVEPqoHaJXuRAnlyly9eEGtu4jFZswA\n" +
            "yzRLCwEZPng7jgfz9FdVZvzuCd4SOoFyxKLwDBCt9uphudW4NfEYDDFlkg94SJqn\n" +
            "4iXAXDO4Ct7LO6qNTrO8IZjNdRUpCk3O49/JOXZ5xJIIkG1r+xOSQHWALDP8W1MI\n" +
            "T/LNFqdaWC6vh1Zf77Z7GhcrKm8VvzDcbOp0XSX9VyfjEtvrHDB7ThlyM0zvBYCS\n" +
            "yjeye4ruPgN7MV6k9LN2fOzE/7FZ93yf+ZvUoJD0ysKrItNvLutuXBdF8fRgWyKk\n" +
            "Uy66949dBcA1O/kC+UIgM98H9P5ZGuc8PcbmVazBwPwKkKFVY5fOV4/STgz8eUi9\n" +
            "KNeq5uEnh1h5RAhIafg14+sFpWv4so3Z7EfETem9pSpO/54RVMzc1+YL5UQ36ljS\n" +
            "46g7H4ZdxvSz6XR8SkHjdzmK+QAam5OU6jidhLoBCbcy17AW3wIhsixJH/r3RRDo\n" +
            "uKu0Q93rVkNjYE/8B9RULBXchciuArJ8iJGenLpC2qqbKfEG2HVOWXHmDiZ6XOaa\n" +
            "Qkl0pkzyRT4f+Groi/igl65KBEi5DsWpsbNmB9TOJF+XuUVzt1zvven5JiHe8ScO\n" +
            "rBE0Lw1qVXt+yXEK0ZRFvYnPeLCEj+rC1vcMzcE0px9i0IFtQ7guDI3zu0YOfqbK\n" +
            "0lWlxdmftT+I1PZLE3NEqDoQPBlfKrILB6y9+jo/WSE9n5kBONSszhiRMxGTJn53\n" +
            "/QJfMA5LCE39W4alipy2157jjy+v1O1MErHztg9XpQs05x0+0CL1l6PSzl/j3u8q\n" +
            "CoU2j5L8o87wj6c3awwqrsQ7W28OVY1RKOUEXZ4ZA2nANfkWpsilMTJBb48sgKwB\n" +
            "jwznJX39DX8KdF4dLpYFNU1VdL5KNdq+MlDTeJbh4AxHUgs5vROQojh+CCPK8Hrd\n" +
            "lSkyeThInF3CihKp7nCJvsrN8U8dZ5rsLA81CVGXZYDH31Ankwlsyfu8/b6kSWeW\n" +
            "dfeAyUiO+FWoyGdWAEXF+oN9HL0AlT6H01lbxzUjIcC0euqvC5qJAZ8EGAEKAAkF\n" +
            "Al4qt70CGwwACgkQ/T3XiRj7WgBfigv+MG0A8eMzt3LpnKmMWdQiAezOfz48AMNr\n" +
            "/tFQXz17SjYPTHAFiNf/jbO7yrpOAGoIxKe0fpotVscWZwaPl5kxHH5+pikAaU6u\n" +
            "/sxWgYQkFDihnLBhl2hfkrU783sz/Rwjgabqm1xjuFJUX8OCzrtb5v1+C/V6tI6h\n" +
            "iDACG6ego1vHJK9hQNb15F7tV+/+xsDgoeE4pCLtU+cjR3MsnTudb8uDmkz5oEey\n" +
            "G29yg8R3x8YGdgogehsWHq/0fQgbTOcfuImNTqZyVAVwZonBTyHMqyLE7J/42iS+\n" +
            "qzJ6swyUgwg+WbACNm/CUvq/0qif3I+zZJ1k29EtG0lLHdXIUuSiJBzN4cKvP655\n" +
            "hmylSI2j6S58HQBJ8VnrPY7FMQZCZymPigx44Tfweu4BAmgBhPP/XH0QHv6VpFtC\n" +
            "iz+cTYFJnjrDlZOsfFE9gY+gnFS4GOdoWj+QP3gN/AGIefAnJWqIQGXG0AYRLiyZ\n" +
            "EHTn0ZhSb3g+06W2Zz4We0QSvA9bHIdu\n" +
            "=iAOI\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v1.62\n" +
            "\n" +
            "lQPGBF33Nf4BCACKLo0AXu/2igGbeNUUmsT00hSCtXyEKh4XtDH0DIMH4FG8G2t1\n" +
            "Tsri8i7ZaTqQpm+Bn37jpP12KN/eyjrjDlJqHIEtIhWiOtAzfWXkr7UnAj1lRf3E\n" +
            "+8WOKRu1YTZqy11SQgWh3YvfdxDZ3xOlHGymXPQna35XD+d1VUKZymmJ4YdsZgmF\n" +
            "ITT2W9BqUp2h6/tuOi9Up/wJ2BioMP0jla5vHwyw8a7jWwbPKdlHNyUpj++G0Q9v\n" +
            "sKOFQL4AQoCdw582T5MiA2FDt2G7E4M1BabI0fFni4Si3jv0s77gidAJWr57jnFA\n" +
            "PU6XmK57JSD5WLfFSeFTveQjsGIrGIA69VupABEBAAH+CQMCObHLjI+SLztgWpKU\n" +
            "8ZZBi0Gxf3KZD1k4Fn7Pde6v3CcB4QQBIFJJChJ0YRCCVkDTh4ai0iDhcx3fFIMo\n" +
            "DSixrJG900xrbG+wF35IjF30ktxLuileFpe82v0TQ7wb1uMi012/2kvm+LNcb//R\n" +
            "Ua76eue6mG4r/p5Uj/UEU84Dq8HThF9a34GzOox28Rc8dg7zgCK4soir06PIdQqj\n" +
            "wmEOMEkzM6ku0vGCC7RACf+lr6Env+hDOs4noa55R98qyX0b8cfKKdw7kq/YThKy\n" +
            "Uv8MusZpeyjxFMQLIhwJa4PHjooOrx4Nhy+inc+snPRpgwyveSOaWkijY2a8WCi/\n" +
            "MKiiRMr8/Aa8NmWGSP7s+BAAkjYDJ0GRD905Sy1/ISrTJ0RlkvLyqHrlCbMjDeEW\n" +
            "gHHkqdEQ6dBd+GP9c0dcT8aqG1tfywd0KGy5afMyaNcabRlNso3pfU+xISGDMz09\n" +
            "gmY+/r0ewL3VPk4F4eS5cTJ9oN9loCIUNdxsDk9+H0+hYrHETrnOfif9vD+hP7bE\n" +
            "rHyISsTXWayH8ik0vPThMuZsEQuYJcC3OAkkMFSpsVHBBa8sJdaBOfa1+qA5hL38\n" +
            "Mv/LoDhyXvm4bkawqfBaOlup62ubwFxVkYly4TnBSxcTNm1l5bKjvDm0W0tDCcrs\n" +
            "XtN6/i95QVCY/XqPoIbzxXu7csEuZfQlggESEQQvRIEd71l8LiFZo2Vs7gHUgPvq\n" +
            "KtqIJAYAMpOBDE5W4TVzeCO4w+vYSXjr8QZJuEsZAOsU8wpYxA66XGthPAK0qey9\n" +
            "EwoOXQytWAvbiC4B/YgW4w4DCUR0B11pTXhNU4/qHFBc/xUcrAEShmg+RsxnMjuc\n" +
            "g+JfMsuiAlrdgQNq1sgBjf/6QiUoDt0DecqAABFZw3yZMOIo7yvxKMrYnpzZ6kvz\n" +
            "dCRqYOLX96xptBU8dGVzdEBhZnRlcmxvZ2ljLmNvbT6JATMEEwEKAB0FAl33Nf4C\n" +
            "Gy8FFgIDAQAECwkIBwUVCgkICwIeAQAKCRARzkSRRETjNUAlB/9U2oa/QPInrevp\n" +
            "PGjw1Y3p5g/9SFSt/Vxrcm+pRaaOhKtBnLwtnk/HqwisUGq9Oa9+cOb5ODd3ioBE\n" +
            "SqwASDHSkPfWcbronroTIIzuE8ZFEhZMxCOiGmnmPeSb8Xzw+WpeT3VH/joXnLlk\n" +
            "Vy9V4kf0UM/rBlFfa8fjdI+jj5/pB06PjEDgZ4rhxj64uPl/Mg4kZQW8UoXUt+tK\n" +
            "+57s7teUqtf+Hcrkoe6S2Xn2BTPiasFIrBpqf0TgZ/FGNbyWGKBRjxXQCl3EIFnT\n" +
            "P+l6+vh6PrVWp0AEvdtU9KRqtlO+c4+W8Ez4e2Vl9i61H3c7QUYKAGty6A6iF9Sl\n" +
            "vbxbQKjw\n" +
            "=+fw1\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n" +
            "\n", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: OpenPGP.js v4.5.5\n" +
            "Comment: https://openpgpjs.org\n" +
            "\n" +
            "xcMGBF2RttoBCACXj7pjhNTU28RsMQgdV0hf8GeshaiVJKHBdBc4kkPPZFVA\n" +
            "pG8jPA2P7LeVYit7KFGHs1U3+OACzCIXRjfenSVJnmk+5QGbcs/ConB8Eay9\n" +
            "ZFN6QjYzXSlwt7w1rkBbdLowUiL9nf6jNkLhxHYK2H1ZsZxlVIY02Jpkqlp6\n" +
            "CDQjSTByfKh0UqVjzKEJuTdPOqEE04y4VhI/p08fSBiQ5ek8WLgbOYgXliog\n" +
            "4yTDzIPxbRV2e9/MTnPgvPS/QDrGmtxlbkAiiChiDKQrjd/Yulb5rq0K1hSC\n" +
            "wNXmtfNbw9pj6lfgvhyYQN4XAwJ3VAV6mpU3BuCPkC1flUORoVqkDIdrABEB\n" +
            "AAH+CQMIUJOzA7UaHKbgqn4dmACswq85XnMsTM/SbXDKxMs+QfrqdfUVs+OM\n" +
            "rsOu8z/d7bSX/PHtP7v/7C2NPgOX/csKJodCSYy8sQLVlA7puzcB14Gz1NeM\n" +
            "qsCACmAg4TNUHk7+a1X5rUbzk5++mAeE2ELtNFN/+CFz4IZnoJ5mGimp45d9\n" +
            "C/Rl1wvUZD5kb5S3o6nrRjlWCIslRFfLyWd/o+17IbyB4Fg7EWugNTyDv2Dt\n" +
            "ArJtiY7poryiCpCYvFDhEoeXGNOeY651Ey7uYDpiKRSqQpENRJPso89An1fz\n" +
            "jF6cv1JhT9OuhKeUD7n5Te+wKEGxGciFVTi9Wxv6Cp5udNkAKZVPof5vtgTK\n" +
            "hUdHuLioLCYn5my3t2h91uwJdekupDa0HFlgZYBeDBloex4s/QdzWhIfH/zy\n" +
            "g9RR5/w5AbBQYaHtvLYcx+WxpPqmyYxjDPkYPPuPNxAWQXAJJWzh6GKUloZH\n" +
            "wxNzIaT4N61WZMEUUiz+TVP+imFtdQmkSyKE2TRITpBahn8SnI0fq+qBSecH\n" +
            "MasbuemQyT9AhWUPOYCRqhAw04EsosXpDdkAYvbHucxz8qopSIKREEAyIt7q\n" +
            "LM0FaMcYIwpIysJBbofAOgZa/ipc9812Vxf0e4wNhieU2LS7VCJPQDHnZTyp\n" +
            "qr2oS+A0A8U+up0yx8cAtwWkqBwUt9wpuY+YzUPBwpjwg90TFYUiaxJHwQe6\n" +
            "rks/wUpIAvcdPXoreBWXr3Ka+ugZwzISOYSl+gM9ZfIX5edQ9EhdwZ4u5tw7\n" +
            "9E1+YDZH9jEFWBBmmGVktOtlQO9GPyo5gcVWfRAxTQnX62gihJgYpQD+qKgv\n" +
            "gcacmIZxtCZBXlWRuAl9dtmBm+tXPX3mU5+2huja0bE3kDh/r32NFiDNh9Bs\n" +
            "1wDXWhrCFECeAACbGgIQbfnVR1Jlzr2vzSFUZXN0ZXIgTmFtZSA8dGVzdEBw\n" +
            "cml2YXRlbWFpbC50dj7CwHUEEAEIAB8FAl2RttoGCwkHCAMCBBUICgIDFgIB\n" +
            "AhkBAhsDAh4BAAoJEPwvW04PjxfwUfIH+wVxndyfOOWpHisI26qlq8SaEhwC\n" +
            "SpiHwKjaaA3dFzTLAjb33PWqq8CIggNCI3NkmNLmj/4kri+P/Cb/FlrTl3Jq\n" +
            "xhtubTCr+LppSEWb4AlGtIqAjjvai40G0UR1AobAjzwpLVRl8t9UKwDCi3G7\n" +
            "1S9TVYq8T+oTZ6Gc5r+CCMsrhOyyxyfue+e5Zh+2TADKPQztKfCPQwgXsC0x\n" +
            "Rkj4POJBWhpFnZbBM+MM1vROdrXF06otZyNM3A2jwTupFW3rXhg+yW5PMuQv\n" +
            "Y3FdDY9pF0McLv9a5OFPWPhmqmP17wtDFNclvx1aNNwGLMVxS7q//fqi8r6d\n" +
            "JD2Bdxm8paVLEhzHwwYEXZG22gEIAMTtVxKcHaPn/ZMNXkXjfc+LOeB0GfSJ\n" +
            "vnyOMvsAOf2Aghmoro5jHCn/Xd0zoFe2qlOUQ7dq8ymV9z7+a7cSYUtba4Sc\n" +
            "rkG55FT8QsBhXGHkaAU9wn83e4vCfjduyd1l3xHmj/oSf/rLfhDTOSObpqdp\n" +
            "X2suGEHUbYY2++BsnaFS8A1QMkJcljbVIKKnzu0RAiaobFeUn/RFC8FUt3sD\n" +
            "sGX/fdPDpyiGxkcSyO3zxHeXB3z0Otz6rfoKkB2rPUJyyjauWAusSVCzi8j/\n" +
            "woH6ljttzREJjxV64qSly2havwXdijMqfNXCPVqtG+Y3oHeWw8n004nP8d8l\n" +
            "HP+ODivpbaEAEQEAAf4JAwgI84t6szwTpOBE/RgCagc2DlnhpfkE5sBVHWA+\n" +
            "AgrxNdIHG1bwxY//HU3UhDcepA/ebSvzGalUKmlmfzcII8YICJCTUSatEzak\n" +
            "uSuqv7VR8A7kcTmRV4wj+EREjvn3ldO7qFLEFzNGydPe82yeFJT1JHMo4Ut1\n" +
            "y2vZP5LmcZ1F79IPH4GwEzzqU0UnAJY7IRgAsUUpc2svWdO1A4vwazdPLqKQ\n" +
            "XAMADCkkT/zL6NYG5aFB1mXSlFYhY09x0uWkVNGL0UcY6Xx8pZMj3srmjH54\n" +
            "bDFstcbenV1V2WbEhe5o1aZo+aByL9FHD4Si/eP5T1zz3TQdfYjmRZSkJ2BT\n" +
            "1qBtEbvdut0n3xuHTLyIieOGRUHafXjyHDoYyRaxXO1pAsbzgUPAwQj3is8E\n" +
            "FjQZHa5Bk5F6O8t7Hv3/vsz9idy+aTc//Yv0qTFiyAmmP4MqdSp2MFiNI+HM\n" +
            "mWsH2tNXCSFSe4tg5CQXpvSi2epHhZeB0/rjR9kqQjc3ozjk3RNdKSY/YdWz\n" +
            "JH9x4ETWAhCIdzEazwfsYi8iGkZOuBwv5ce89BFwqrvzCH6fHbqGkmskc/Ab\n" +
            "Dt2r7TH03hityoX2sT0RliJitfTJkGFjivhwMGBe6IyAce0r0TS0cPukxwr6\n" +
            "+CVqYf53F2Aa0/bDjTWR6xBOqisKYGu9AJw3df3UEGBobIzOcfzWe5Mqq/3O\n" +
            "wyfj9Bn1cdU+375AiKRFMkLuidKFGXqLYVQLd0GTJFhkJ6W3gySvNec4L21U\n" +
            "qWgSISdxJTcLVS9C4oZf9XIYIXEk+OyPCSnnOkeHCZovABCTqoeda4/pD/9N\n" +
            "ZiQz1LjC582KeEnsOnJ0el3ASGUWVOPM4lMVMTooAUxHtUfGYNN35D73UDHW\n" +
            "ACoe3a/dNVzE9HUvEk/+CTYjw4qXD/3loXJH9tyR3mXki8vCwF8EGAEIAAkF\n" +
            "Al2RttoCGwwACgkQ/C9bTg+PF/CWswgAhV0exUGS/MaUPNXtNyIfIcc47me6\n" +
            "AdE3qeKkC8ZHLjytBfT90tiFHcZ61oDFHj5vIWWDdvJhMBi6ohs21cn18JTZ\n" +
            "wR1qjp5xFpRQpP3+UCgI0CZG1eml3hVEzVghD27BpDXELsHbZATs7W3KnAsM\n" +
            "Nz8dVRMwGdTvfARbq4jwyDCqUgaVeDDlKf3ipVEcoq/ihsCFT+9m4e9DdZ/v\n" +
            "xwgQNl7YFMhvsT1Ai/rCFIRGGKnDV+zhXLmSTqpX5wL5IV8l4NqyU7dUvBvS\n" +
            "j2j8vduthVkt5tLB2yoaAn8m6T9XwMaRx5L1/+/WLAD5gUV3WHFb1NuUx8IJ\n" +
            "x9NeEajgZI6DGQ==\n" +
            "=48ti\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n")
    val testPublicKeys = arrayListOf<String>("-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Generated by DMSOpenPGP\n" +
            "\n" +
            "mQGNBF4qt7sBDADQi8om7zEJZvy4Ng/kn2u6NKe262xPj1tpktCZ0/5K6eeC1Gp9\n" +
            "dwxG4BTIBQNaTiRr3w6gNZLGk04/T8Hlwv0h+RdYQVKreD8gj5/Rexuxv68MdU1u\n" +
            "mgHwqZNmsa8Hris2oVBkV5opBJbO7xnQxnk8rcwbWljcbSNgam0cnqBr+oMlXwz+\n" +
            "RjoNfTfAQtSczZhYW5y/3/MjGPZu0vwkVbbf9jDYctk0FfKbtuzqNTusCeBi9GAk\n" +
            "clwMPU68T5oz8Cw5B+rLxoDjp6pQTgGbWpqKwj8ewvRVifPXndvbV+RGQqoxy+vX\n" +
            "0Ir9TgejhyPrSL+MV6XMn/GHVbCpFtbDQ1dOzOhL2XKU6tvVXh1y9315T8Cux8OJ\n" +
            "5o4P7gOcll75BJi/zYKHjYC26DF1hIKBC9AAXLdm5xcwvEyk73ojTX+Y2vQNGj0y\n" +
            "yeyUZ5i7M2QhxqO0N9I/VmeFCIYdro5Xsz6znWHwZpu7xs54hBadIVr7iWusfyGv\n" +
            "h+eEe8NKRyCIgd8AEQEAAbQhIDxnb29nbGVwbGF5dGVzdEBwcml2YXRlbWFpbC5j\n" +
            "b20+iQGuBBMBCgAYBQJeKre9AhsDBAsJCAcGFQgCCQoLAh4BAAoJEP0914kY+1oA\n" +
            "DOEMAMi2xixLL/KFTPqNZNovQjtHDTJCxtIoymze1gquM5WjmuMasn4BlOei5/WU\n" +
            "/dgUoTQ0h9MKbEt+0jpQA89XIc6IBeiQaKu40eaRwzLB0BVgVCCdPwrbexjPqio7\n" +
            "eKJo1YCBL1eKA/RPREZ4qITCImaFisFeJOj2rzyUySg1O4YJW932BnN7tm8SpFrq\n" +
            "Y1V5kyx3O9hYm+DG1LybCNr7pQlU8sOgqA6AdJgmiGyJGT+hlFg43ZH3oouSPhM5\n" +
            "YNDPEKmb7QUDgBLPXsJlEhzZSxzo62Oy/ysSC5cCdtIVXrXXsmJGhnLRteRzGEuU\n" +
            "L4ct1C3y5aB23cmRAIFTjNGNvjnzPc7Kl+gs1apkHEcoW1zInvHs9qx8ekMqEQO/\n" +
            "VHb75uxJPP8lRGeV7L7rTnjXNaS/8FzxJ19SpcoGrgtUHjXudXwmCcIkiZHwnuM+\n" +
            "KT4AFrSVcAYVwru5NJ53qVJ7SBoTq0BtauV1TzGrkERHkbtBUsJfwyGX81Z44Nx1\n" +
            "o4G+b7kBjQReKre7AQwAvLpI5TFP5MuoyEC4xd+W0kut52P83c+xoRKcAjbv6xY4\n" +
            "j+muo5JaPYQuYxNKv2qJdVvNYBc6BBFQuAQyjHA8t0FOU4YK8uOGgO+I9U7Bd6FK\n" +
            "9GW2eYY0Gf+XcGPGUNfyUT+j2d6gr6+mjbri0aeiqMp2iSWd17a0Sj/05oXXsUfv\n" +
            "8kXvYBgrU/9FAkr9W+x7AQ6EIGMpTctCcWFq7d9o1o9Ih5apCpueN6MLlSiyAVPJ\n" +
            "YIBM3ypG8b8J8+6SMGZGEJc8apyvV2/Cli/n67A3DdKg9VmbeY9Rno/87gPtdBWB\n" +
            "QwIS/YSAPB89rDF907A3/bZt1qihc+ZK4voCyDiSeHsvkmDkLhKkS796o8PTrKn2\n" +
            "92uE/6SJm4Q20XhtTujNGIRsyK90Vj6aOf82wTYNqu4DLcxeDiCUHM8z7cNgi6aT\n" +
            "n2DXffldVypGl3Yoje95z1gXStFP/hSv5MqjvcKcpAEP9XE/QiSuKE8KbaTJlvoN\n" +
            "YMn0+SO7Bos+svhUB8IJABEBAAGJAZ8EGAEKAAkFAl4qt70CGwwACgkQ/T3XiRj7\n" +
            "WgBfigv+MG0A8eMzt3LpnKmMWdQiAezOfz48AMNr/tFQXz17SjYPTHAFiNf/jbO7\n" +
            "yrpOAGoIxKe0fpotVscWZwaPl5kxHH5+pikAaU6u/sxWgYQkFDihnLBhl2hfkrU7\n" +
            "83sz/Rwjgabqm1xjuFJUX8OCzrtb5v1+C/V6tI6hiDACG6ego1vHJK9hQNb15F7t\n" +
            "V+/+xsDgoeE4pCLtU+cjR3MsnTudb8uDmkz5oEeyG29yg8R3x8YGdgogehsWHq/0\n" +
            "fQgbTOcfuImNTqZyVAVwZonBTyHMqyLE7J/42iS+qzJ6swyUgwg+WbACNm/CUvq/\n" +
            "0qif3I+zZJ1k29EtG0lLHdXIUuSiJBzN4cKvP655hmylSI2j6S58HQBJ8VnrPY7F\n" +
            "MQZCZymPigx44Tfweu4BAmgBhPP/XH0QHv6VpFtCiz+cTYFJnjrDlZOsfFE9gY+g\n" +
            "nFS4GOdoWj+QP3gN/AGIefAnJWqIQGXG0AYRLiyZEHTn0ZhSb3g+06W2Zz4We0QS\n" +
            "vA9bHIdu\n" +
            "=RLjS\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: BCPG v1.62\n" +
            "\n" +
            "mQENBF33Nf4BCACKLo0AXu/2igGbeNUUmsT00hSCtXyEKh4XtDH0DIMH4FG8G2t1\n" +
            "Tsri8i7ZaTqQpm+Bn37jpP12KN/eyjrjDlJqHIEtIhWiOtAzfWXkr7UnAj1lRf3E\n" +
            "+8WOKRu1YTZqy11SQgWh3YvfdxDZ3xOlHGymXPQna35XD+d1VUKZymmJ4YdsZgmF\n" +
            "ITT2W9BqUp2h6/tuOi9Up/wJ2BioMP0jla5vHwyw8a7jWwbPKdlHNyUpj++G0Q9v\n" +
            "sKOFQL4AQoCdw582T5MiA2FDt2G7E4M1BabI0fFni4Si3jv0s77gidAJWr57jnFA\n" +
            "PU6XmK57JSD5WLfFSeFTveQjsGIrGIA69VupABEBAAG0FTx0ZXN0QGFmdGVybG9n\n" +
            "aWMuY29tPokBMwQTAQoAHQUCXfc1/gIbLwUWAgMBAAQLCQgHBRUKCQgLAh4BAAoJ\n" +
            "EBHORJFEROM1QCUH/1Tahr9A8iet6+k8aPDVjenmD/1IVK39XGtyb6lFpo6Eq0Gc\n" +
            "vC2eT8erCKxQar05r35w5vk4N3eKgERKrABIMdKQ99ZxuuieuhMgjO4TxkUSFkzE\n" +
            "I6IaaeY95JvxfPD5al5PdUf+OhecuWRXL1XiR/RQz+sGUV9rx+N0j6OPn+kHTo+M\n" +
            "QOBniuHGPri4+X8yDiRlBbxShdS360r7nuzu15Sq1/4dyuSh7pLZefYFM+JqwUis\n" +
            "Gmp/ROBn8UY1vJYYoFGPFdAKXcQgWdM/6Xr6+Ho+tVanQAS921T0pGq2U75zj5bw\n" +
            "TPh7ZWX2LrUfdztBRgoAa3LoDqIX1KW9vFtAqPA=\n" +
            "=+UBo\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "\n", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: OpenPGP.js v4.5.5\n" +
            "Comment: https://openpgpjs.org\n" +
            "\n" +
            "xsBNBF2RttoBCACXj7pjhNTU28RsMQgdV0hf8GeshaiVJKHBdBc4kkPPZFVA\n" +
            "pG8jPA2P7LeVYit7KFGHs1U3+OACzCIXRjfenSVJnmk+5QGbcs/ConB8Eay9\n" +
            "ZFN6QjYzXSlwt7w1rkBbdLowUiL9nf6jNkLhxHYK2H1ZsZxlVIY02Jpkqlp6\n" +
            "CDQjSTByfKh0UqVjzKEJuTdPOqEE04y4VhI/p08fSBiQ5ek8WLgbOYgXliog\n" +
            "4yTDzIPxbRV2e9/MTnPgvPS/QDrGmtxlbkAiiChiDKQrjd/Yulb5rq0K1hSC\n" +
            "wNXmtfNbw9pj6lfgvhyYQN4XAwJ3VAV6mpU3BuCPkC1flUORoVqkDIdrABEB\n" +
            "AAHNIVRlc3RlciBOYW1lIDx0ZXN0QHByaXZhdGVtYWlsLnR2PsLAdQQQAQgA\n" +
            "HwUCXZG22gYLCQcIAwIEFQgKAgMWAgECGQECGwMCHgEACgkQ/C9bTg+PF/BR\n" +
            "8gf7BXGd3J845akeKwjbqqWrxJoSHAJKmIfAqNpoDd0XNMsCNvfc9aqrwIiC\n" +
            "A0Ijc2SY0uaP/iSuL4/8Jv8WWtOXcmrGG25tMKv4umlIRZvgCUa0ioCOO9qL\n" +
            "jQbRRHUChsCPPCktVGXy31QrAMKLcbvVL1NVirxP6hNnoZzmv4IIyyuE7LLH\n" +
            "J+5757lmH7ZMAMo9DO0p8I9DCBewLTFGSPg84kFaGkWdlsEz4wzW9E52tcXT\n" +
            "qi1nI0zcDaPBO6kVbeteGD7Jbk8y5C9jcV0Nj2kXQxwu/1rk4U9Y+GaqY/Xv\n" +
            "C0MU1yW/HVo03AYsxXFLur/9+qLyvp0kPYF3GbylpUsSHM7ATQRdkbbaAQgA\n" +
            "xO1XEpwdo+f9kw1eReN9z4s54HQZ9Im+fI4y+wA5/YCCGaiujmMcKf9d3TOg\n" +
            "V7aqU5RDt2rzKZX3Pv5rtxJhS1trhJyuQbnkVPxCwGFcYeRoBT3Cfzd7i8J+\n" +
            "N27J3WXfEeaP+hJ/+st+ENM5I5ump2lfay4YQdRthjb74GydoVLwDVAyQlyW\n" +
            "NtUgoqfO7RECJqhsV5Sf9EULwVS3ewOwZf9908OnKIbGRxLI7fPEd5cHfPQ6\n" +
            "3Pqt+gqQHas9QnLKNq5YC6xJULOLyP/CgfqWO23NEQmPFXripKXLaFq/Bd2K\n" +
            "Myp81cI9Wq0b5jegd5bDyfTTic/x3yUc/44OK+ltoQARAQABwsBfBBgBCAAJ\n" +
            "BQJdkbbaAhsMAAoJEPwvW04PjxfwlrMIAIVdHsVBkvzGlDzV7TciHyHHOO5n\n" +
            "ugHRN6nipAvGRy48rQX0/dLYhR3GetaAxR4+byFlg3byYTAYuqIbNtXJ9fCU\n" +
            "2cEdao6ecRaUUKT9/lAoCNAmRtXppd4VRM1YIQ9uwaQ1xC7B22QE7O1typwL\n" +
            "DDc/HVUTMBnU73wEW6uI8MgwqlIGlXgw5Sn94qVRHKKv4obAhU/vZuHvQ3Wf\n" +
            "78cIEDZe2BTIb7E9QIv6whSERhipw1fs4Vy5kk6qV+cC+SFfJeDaslO3VLwb\n" +
            "0o9o/L3brYVZLebSwdsqGgJ/Juk/V8DGkceS9f/v1iwA+YFFd1hxW9TblMfC\n" +
            "CcfTXhGo4GSOgxk=\n" +
            "=gtgB\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n")
}