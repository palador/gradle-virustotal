package de.palador.gradle.vt

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.kanishka.virustotal.exception.QuotaExceededException
import com.kanishka.virustotalv2.VirustotalPublicV2
import org.gradle.api.Project
import org.gradle.api.logging.Logger
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.MessageDigest
import javax.xml.bind.DatatypeConverter

val _PRIVATE_jsonMapper = ObjectMapper().also {
    it.registerKotlinModule()
    it.enable(SerializationFeature.INDENT_OUTPUT)
    it.enable(SerializationFeature.CLOSE_CLOSEABLE)
}

fun Any.serializeJson(os: OutputStream) {
    _PRIVATE_jsonMapper.writeValue(os, this)
}

fun Any.serializeJsonAsString() = _PRIVATE_jsonMapper.writeValueAsString(this)

inline fun <reified T> InputStream.deserializeJson(): T {
    return _PRIVATE_jsonMapper.readValue(this, T::class.java)
}

inline fun <reified T> String.deserializeJson(): T {
    return _PRIVATE_jsonMapper.readValue(this, T::class.java)
}

fun InputStream.sha256(): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    val buf = ByteArray(4096)
    while (true) {
        val len = read(buf)
        if (len <= 0) break

        md.update(buf, 0, len)
    }

    return md.digest()
}

fun InputStream.sha256string() = DatatypeConverter.printHexBinary(sha256())!!.toLowerCase()

fun File.sha256() = inputStream().sha256()

fun File.sha256string() = inputStream().sha256string()

fun <T> VirustotalPublicV2.run(
        operationName: String,
        logger: Logger,
        op: VirustotalPublicV2.() -> T)
        : T? {
    while (true) {
        try {
            return op()
        } catch (e: QuotaExceededException) {
            Thread.sleep(61L * 1000L)
            continue
        } catch (e: Exception) {
            logger.error("$operationName failed", e)
            return null
        }
    }
}