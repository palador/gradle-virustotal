package de.palador.gradle.vt

import com.kanishka.virustotal.dto.FileScanReport
import com.kanishka.virustotal.dto.ScanInfo
import org.gradle.api.logging.Logger
import java.io.File
import java.io.FileNotFoundException

class Database(
        private val logger: Logger,
        private val dir: File
) {

    private val scanInfoDir = File(dir, "scanInfo")
            .also { it.mkdirs() }

    private val scanReportDir = File(dir, "scanReport")
            .also { it.mkdirs() }

    fun getScanInfo(sha256: String): ScanInfo? {
        val file = File(scanInfoDir, sha256)
        return try {
            file.inputStream().deserializeJson<ScanInfo>()
        } catch (e: Exception) {
            if (e !is FileNotFoundException)
                logger.error("failed to read cached scan info", e)
            null
        }
    }

    fun writeScanInfo(scanInfo: ScanInfo, sha256: String) {
        if (scanInfo.responseCode != VirusTotalResponseCodes.Scan.queued) {
            logger.error("can't write scan info, because of unexpected responseCode: ${scanInfo.responseCode}")
            return
        }

        val file = File(scanInfoDir, sha256)
        try {
            scanInfo.serializeJson(file.outputStream())
        } catch (e: Exception) {
            logger.error("failed to write scan info to cache", e)
        }
    }

    fun readScanReport(sha256: String): FileScanReport? {
        val file = File(scanReportDir, sha256)
        return try {
            file.inputStream().deserializeJson<FileScanReport>()
        } catch (e: Exception) {
            if (e !is FileNotFoundException)
                logger.error("failed to read cached scan report", e)
            null
        }
    }

    fun writeScanReport(scanReport: FileScanReport, sha256: String) {
        if (scanReport.responseCode != VirusTotalResponseCodes.Report.present) {
            logger.error("can't write report, because of unexpected response code: ${scanReport.responseCode}")
            return
        }
        val file = File(scanReportDir, sha256)
        try {
            scanReport.serializeJson(file.outputStream())
        } catch (e: Exception) {
            logger.error("failed to write scan report to cache")
        }
    }
}
