#!/usr/bin/env kotlin
@file:kotlin.script.experimental.dependencies.DependsOn("jakarta.mail:jakarta.mail-api:2.2.0-M1")
@file:kotlin.script.experimental.dependencies.DependsOn("org.eclipse.angus:angus-mail:2.0.4")
@file:kotlin.script.experimental.dependencies.DependsOn("jakarta.activation:jakarta.activation-api:2.1.3")
@file:kotlin.script.experimental.dependencies.DependsOn("org.eclipse.angus:angus-activation:2.0.2")
@file:kotlin.script.experimental.dependencies.DependsOn("org.apache.commons:commons-compress:1.28.0")
@file:kotlin.script.experimental.dependencies.DependsOn("org.tukaani:xz:1.9")
@file:kotlin.script.experimental.dependencies.DependsOn("net.sf.cssbox:swingbox:1.1")
@file:Suppress("MemberVisibilityCanBePrivate")

import java.awt.BorderLayout
import java.awt.Desktop
import java.awt.Dimension
import java.awt.EventQueue
import java.awt.Toolkit
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.StringReader
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection
import java.text.DecimalFormat
import java.util.Locale
import java.util.Properties
import javax.swing.BorderFactory
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JFileChooser
import javax.swing.JMenu
import javax.swing.JMenuBar
import javax.swing.JMenuItem
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JEditorPane
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.ListSelectionModel
import javax.swing.KeyStroke
import javax.swing.SwingUtilities
import javax.swing.SwingWorker
import javax.swing.filechooser.FileNameExtensionFilter
import javax.swing.text.DefaultCaret
import jakarta.mail.BodyPart
import jakarta.mail.Multipart
import jakarta.mail.Part
import jakarta.mail.Session
import jakarta.mail.internet.MimeUtility
import jakarta.mail.internet.MimeMessage
import org.apache.commons.compress.PasswordRequiredException
import org.apache.commons.compress.archivers.sevenz.SevenZFile
import org.fit.cssbox.swingbox.SwingBoxEditorKit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempFile
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.name
import kotlin.io.path.extension
import kotlin.io.path.deleteIfExists
import kotlin.system.exitProcess

val isHeadlessEnvironment = java.lang.Boolean.getBoolean("java.awt.headless")
if (isHeadlessEnvironment && args.none { it == "--cli" }) {
    relaunchWithGui(args)
}

data class EmailSummary(
    val index: Int,
    val envelopeFromLine: String,
    val from: String,
    val subject: String,
    val date: String,
    val hasAttachments: Boolean
)

data class EmailMessage(
    val index: Int,
    val envelopeFromLine: String,
    val headers: Map<String, List<String>>,
    val body: String
) {
    val subjectLine: String = headers.firstHeaderValue("Subject") ?: "(no subject)"
    val fromLine: String = headers.firstHeaderValue("From") ?: envelopeFromLine.defaultSender()
    val dateLine: String = headers.firstHeaderValue("Date") ?: "(no date)"
}

data class AttachmentInfo(
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long?,
    val bodyPart: BodyPart
) {
    override fun toString(): String {
        val sizeText = sizeBytes?.let { formatSize(it) } ?: "unknown size"
        return "$displayName ($mimeType, $sizeText)"
    }
}

data class InlineImageContent(
    val mimeType: String,
    val data: ByteArray
)

data class MessageDetail(
    val email: EmailMessage,
    val mimeMessage: MimeMessage,
    val attachments: List<AttachmentInfo>,
    val preferredText: String,
    val htmlContent: String?,
    val inlineImages: Map<String, InlineImageContent>
)

private enum class RunMode { GUI, CLI }

private data class Options(
    val mboxPath: Path?,
    val messageIndex: Int?,
    val includeHeaders: Boolean,
    val searchTerm: String?,
    val mode: RunMode,
    val password: CharArray?
)

private data class InitialSelection(val path: Path, val password: CharArray?)

private sealed interface MailboxSource {
    val sourcePath: Path
    val displayName: String
    fun openReader(): BufferedReader
}

private class FileMailboxSource(private val path: Path) : MailboxSource {
    override val sourcePath: Path = path
    override val displayName: String = path.name
    override fun openReader(): BufferedReader = Files.newBufferedReader(path, StandardCharsets.ISO_8859_1)
}

private class InMemoryMailboxSource(
    override val sourcePath: Path,
    private val entryName: String,
    private val content: ByteArray
) : MailboxSource {
    override val displayName: String = "${sourcePath.name}/$entryName"
    override fun openReader(): BufferedReader =
        ByteArrayInputStream(content).bufferedReader(StandardCharsets.ISO_8859_1)
}

private enum class PasswordFailureReason { REQUIRED, INVALID }

private class MailboxPasswordException(
    val reason: PasswordFailureReason,
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

private class MailboxFormatException(message: String, cause: Throwable? = null) : Exception(message, cause)

private fun openMailboxSource(path: Path, password: CharArray?): MailboxSource {
    if (!path.exists() || !path.isRegularFile()) {
        throw MailboxFormatException("File not found or not a regular file: $path")
    }
    return if (path.isSevenZip()) {
        openSevenZipMailbox(path, password)
    } else {
        FileMailboxSource(path)
    }
}

private fun Path.isSevenZip(): Boolean = extension.equals("7z", ignoreCase = true)

private fun openSevenZipMailbox(path: Path, password: CharArray?): MailboxSource {
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    try {
        val sevenZ = if (password != null) SevenZFile(path.toFile(), password) else SevenZFile(path.toFile())
        sevenZ.use { archive ->
            var entryName: String? = null
            var data: ByteArray? = null
            while (true) {
                val entry = archive.nextEntry ?: break
                if (entry.isDirectory) continue
                if (entryName != null) {
                    throw MailboxFormatException("Archive ${path.name} contains multiple files; expected a single .mbox entry.")
                }
                val out = ByteArrayOutputStream()
                while (true) {
                    val read = archive.read(buffer)
                    if (read < 0) break
                    out.write(buffer, 0, read)
                }
                entryName = entry.name
                data = out.toByteArray()
            }
            if (entryName == null || data == null) {
                throw MailboxFormatException("Archive ${path.name} does not contain a file entry.")
            }
            if (!entryName.endsWith(".mbox", ignoreCase = true)) {
                System.err.println("Warning: archive entry '$entryName' does not end with .mbox; continuing anyway.")
            }
            return InMemoryMailboxSource(path, entryName!!, data!!)
        }
    } catch (ex: PasswordRequiredException) {
        throw MailboxPasswordException(PasswordFailureReason.REQUIRED, "Password required for archive ${path.name}", ex)
    } catch (ex: IOException) {
        val message = ex.message?.lowercase(Locale.ROOT) ?: ""
        val indicatesPassword = message.contains("password") || message.contains("decrypt") || message.contains("wrong") || message.contains("corrupt") || message.contains("checksum")
        if (indicatesPassword || password != null) {
            throw MailboxPasswordException(PasswordFailureReason.INVALID, "Invalid password for archive ${path.name}", ex)
        }
        throw MailboxFormatException("Failed to read archive ${path.name}: ${ex.message}", ex)
    }
}

private fun usage(): Nothing {
    val program = Paths.get(System.getProperty("kotlin.script.file") ?: "mbox_reader.main.kts").fileName.toString()
    System.err.println(
        """
        Usage: $program [--cli] [--mbox <path>] [--message <index>] [--headers] [--search <term>] [--password [<value>]]

        Arguments:
          --mbox, -m          Path to the mbox file to read (optional in GUI mode; required in CLI mode).
          --cli               Run in command-line mode (disables GUI output).
          --message, -i       Show the full message for the given 1-based index (CLI mode).
          --headers           Include all headers when printing a message body (CLI mode).
          --search, -s        Filter summaries to messages where From, Subject, or Date contain the term (CLI mode).
          --password, -p      Provide an archive password (omit the value to be prompted on stdin).
          --help, -h          Display this help information and exit.

        Examples:
          $program --mbox archive.mbox               # Launch GUI with archive.mbox loaded
          $program --mbox archive.7z --password      # Launch GUI with archive.7z and prompt for password
          $program --cli --mbox archive.mbox --message 5
        """.trimIndent()
    )
    exitProcess(1)
}

private fun relaunchWithGui(originalArgs: Array<String>): Nothing {
    val scriptFileProperty = System.getProperty("kotlin.script.file")
    val scriptPath = scriptFileProperty?.let { Paths.get(it).toAbsolutePath().normalize() }
        ?: Paths.get("").toAbsolutePath().resolve("mbox_reader.main.kts").takeIf { it.exists() }
    if (scriptPath == null) {
        System.err.println("Unable to determine script path for GUI relaunch. Re-run with --cli or set java.awt.headless=false.")
        exitProcess(1)
    }

    val commandLine = buildRelaunchCommand(scriptPath, originalArgs)
    val invocation = defaultShellInvocation(commandLine)

    try {
        val process = ProcessBuilder(invocation)
            .redirectInput(ProcessBuilder.Redirect.INHERIT)
            .redirectOutput(ProcessBuilder.Redirect.INHERIT)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start()
        val exitCode = try {
            process.waitFor()
        } catch (interrupted: InterruptedException) {
            process.destroy()
            Thread.currentThread().interrupt()
            -1
        }
        exitProcess(exitCode)
    } catch (ex: Exception) {
        System.err.println("Failed to relaunch GUI process: ${ex.message}")
        exitProcess(1)
    }
}

private fun buildRelaunchCommand(scriptPath: Path, originalArgs: Array<String>): String {
    val osName = System.getProperty("os.name").lowercase(Locale.ROOT)
    val baseArgs = buildList {
        add("kotlin")
        add("-Djava.awt.headless=false")
        add(scriptPath.toString())
        addAll(originalArgs)
    }
    return if (osName.contains("win")) {
        baseArgs.joinToString(" ") { windowsShellQuote(it) }
    } else {
        baseArgs.joinToString(" ") { posixShellQuote(it) }
    }
}

private fun defaultShellInvocation(command: String): List<String> {
    val osName = System.getProperty("os.name").lowercase(Locale.ROOT)
    return if (osName.contains("win")) {
        val shell = System.getenv("ComSpec").takeUnless { it.isNullOrBlank() } ?: "cmd.exe"
        listOf(shell, "/c", command)
    } else {
        val shell = System.getenv("SHELL").takeUnless { it.isNullOrBlank() } ?: "/bin/sh"
        listOf(shell, "-c", command)
    }
}

private fun posixShellQuote(value: String): String =
    if (value.isEmpty()) "''" else "'" + value.replace("'", "'\\''") + "'"

private fun windowsShellQuote(value: String): String {
    if (value.isEmpty()) return "\"\""
    val needsQuotes = value.any { it.isWhitespace() || it in listOf('^', '&', '|', '<', '>', '(', ')') }
    var escaped = value.replace("\"", "\"\"")
    if (needsQuotes) {
        escaped = "\"$escaped\""
    }
    return escaped
}

private fun promptPasswordFromStdIn(): CharArray {
    print("Password: ")
    System.out.flush()
    return readLine()?.toCharArray() ?: CharArray(0)
}

private fun parseArgs(args: Array<String>): Options {
    var mboxArg: String? = null
    var messageIndex: Int? = null
    var includeHeaders = false
    var searchTerm: String? = null
    var forceCli = false
    var passwordChars: CharArray? = null
    var passwordNeedsPrompt = false
    var passwordOptionSeen = false

    var i = 0
    while (i < args.size) {
        val token = args[i]
        when {
            token.startsWith("--mbox=") -> {
                val value = token.substringAfter("=")
                if (value.isBlank()) {
                    System.err.println("--mbox requires a value")
                    usage()
                }
                if (mboxArg != null) {
                    System.err.println("Multiple --mbox values provided: '$mboxArg' and '$value'")
                    usage()
                }
                mboxArg = value
            }

            token.startsWith("--password=") -> {
                if (passwordOptionSeen) {
                    System.err.println("Multiple --password values provided")
                    usage()
                }
                passwordOptionSeen = true
                val value = token.substringAfter("=")
                if (value.isEmpty()) {
                    passwordNeedsPrompt = true
                } else {
                    passwordChars = value.toCharArray()
                }
            }

            else -> when (token) {
                "--mbox", "-m" -> {
                    if (i + 1 >= args.size) {
                        System.err.println("Missing value for $token")
                        usage()
                    }
                    val value = args[++i]
                    if (mboxArg != null) {
                        System.err.println("Multiple --mbox values provided: '$mboxArg' and '$value'")
                        usage()
                    }
                    mboxArg = value
                }

                "--cli" -> forceCli = true

                "--message", "-i" -> {
                    if (i + 1 >= args.size) {
                        System.err.println("Missing value for $token")
                        usage()
                    }
                    val value = args[++i]
                    val parsed = value.toIntOrNull()?.takeIf { it > 0 } ?: run {
                        System.err.println("Invalid message index: $value")
                        usage()
                    }
                    messageIndex = parsed
                    forceCli = true
                }

                "--headers" -> {
                    includeHeaders = true
                    forceCli = true
                }

                "--search", "-s" -> {
                    if (i + 1 >= args.size) {
                        System.err.println("Missing value for $token")
                        usage()
                    }
                    val value = args[++i]
                    searchTerm = value
                    forceCli = true
                }

                "--password", "-p" -> {
                    if (passwordOptionSeen) {
                        System.err.println("Multiple --password values provided")
                        usage()
                    }
                    passwordOptionSeen = true
                    val hasValue = i + 1 < args.size && !args[i + 1].startsWith("-")
                    if (hasValue) {
                        val value = args[++i]
                        passwordChars = value.toCharArray()
                    } else {
                        passwordNeedsPrompt = true
                    }
                }

                "--help", "-h" -> usage()

                else -> {
                    System.err.println("Unknown option: $token")
                    usage()
                }
            }
        }
        i++
    }

    val mode = if (forceCli) RunMode.CLI else RunMode.GUI

    if (passwordNeedsPrompt) {
        passwordChars = promptPasswordFromStdIn()
    }

    val resolvedPath = mboxArg?.let {
        val resolved = Paths.get(it).toAbsolutePath().normalize()
        if (!resolved.exists() || !resolved.isRegularFile()) {
            System.err.println("File not found or not a regular file: $resolved")
            exitProcess(2)
        }
        resolved
    }

    if (mode == RunMode.CLI && resolvedPath == null) {
        System.err.println("--cli mode requires --mbox <path>.")
        usage()
    }

    return Options(
        resolvedPath,
        messageIndex,
        includeHeaders,
        searchTerm?.lowercase(),
        mode,
        passwordChars?.copyOf()
    )
}

private fun Map<String, List<String>>.firstHeaderValue(key: String): String? =
    this[key]?.firstOrNull()?.takeIf { it.isNotBlank() }

private fun String.defaultSender(): String =
    removePrefix("From ").trim().ifBlank { "(unknown sender)" }

private fun headersIndicateAttachments(headers: Map<String, List<String>>): Boolean {
    val contentTypeValues = headers["Content-Type"].orEmpty()
    for (value in contentTypeValues) {
        val normalized = value.lowercase(Locale.ROOT)
        if (normalized.contains("multipart/mixed") ||
            normalized.contains("multipart/related") ||
            normalized.contains("multipart/report") ||
            normalized.contains("multipart/signed") ||
            normalized.contains("multipart/appledouble") ||
            (normalized.contains("multipart/") && !normalized.contains("multipart/alternative") && normalized.contains("boundary="))
        ) {
            return true
        }
        if (normalized.contains("name=") && !normalized.contains("text/plain") && !normalized.contains("text/html")) {
            return true
        }
    }
    val dispositionValues = headers["Content-Disposition"].orEmpty()
    if (dispositionValues.any { it.contains("attachment", ignoreCase = true) || it.contains("filename=", ignoreCase = true) }) {
        return true
    }
    val attachmentIds = headers["X-Attachment-Id"].orEmpty()
    if (attachmentIds.isNotEmpty()) {
        return true
    }
    return false
}

private fun analyzeMimeLineForAttachment(line: String, activeHeader: String?): Pair<Boolean, String?> {
    if (line.isEmpty()) return false to null
    if (line.startsWith("--")) return false to null
    val trimmed = line.trimStart()
    val lower = trimmed.lowercase(Locale.ROOT)
    return when {
        line.startsWith(" ") || line.startsWith("\t") -> {
            val header = activeHeader
            val indicates = when (header) {
                "content-disposition" -> lower.contains("attachment") || lower.contains("filename=")
                "content-type" -> lower.contains("name=") && !lower.contains("text/plain") && !lower.contains("text/html")
                else -> lower.contains("filename=")
            }
            indicates to header
        }
        !line.contains(":") -> {
            (lower.contains("filename=") || lower.contains("begin 644")) to activeHeader
        }
        else -> {
            val name = line.substringBefore(':').lowercase(Locale.ROOT)
            val valueLower = line.substringAfter(':').lowercase(Locale.ROOT)
            val indicates = when (name) {
                "content-disposition" -> valueLower.contains("attachment") || valueLower.contains("filename=")
                "content-type" -> (valueLower.contains("name=") && !valueLower.contains("text/plain") && !valueLower.contains("text/html")) ||
                    (valueLower.startsWith("application/") && valueLower.contains("name="))
                "x-attachment-id" -> true
                "content-description" -> true
                else -> valueLower.contains("filename=")
            }
            indicates to name
        }
    }
}

private fun iterateMessages(
    source: MailboxSource,
    needsBody: (Int) -> Boolean,
    onMessage: (index: Int, envelope: String, headers: Map<String, List<String>>, body: String?, attachmentHint: Boolean) -> Boolean
) {
    source.openReader().use { reader ->
        var nextEnvelope: String? = null
        var messageCounter = 0

        mainLoop@ while (true) {
            val envelope = nextEnvelope ?: reader.readLine() ?: break
            nextEnvelope = null
            if (!envelope.startsWith("From ")) {
                continue
            }

            messageCounter++
            val headerLines = mutableListOf<String>()
            var reachedEOF = false
            var line: String?

            while (true) {
                line = reader.readLine()
                if (line == null) {
                    reachedEOF = true
                    break
                }
                if (line.isEmpty()) {
                    break
                }
                headerLines += line
            }

            val headers = parseHeaders(headerLines)
            val collectBody = needsBody(messageCounter)
            val bodyLines = if (collectBody) mutableListOf<String>() else null
            var attachmentHint = headersIndicateAttachments(headers)
            var activeMimeHeader: String? = null

            if (!reachedEOF) {
                while (true) {
                    line = reader.readLine()
                    if (line == null) {
                        reachedEOF = true
                        break
                    }
                    if (line.startsWith("From ")) {
                        nextEnvelope = line
                        break
                    }
                    val (foundAttachment, headerName) = analyzeMimeLineForAttachment(line, activeMimeHeader)
                    if (!attachmentHint && foundAttachment) {
                        attachmentHint = true
                    }
                    activeMimeHeader = headerName
                    bodyLines?.add(line)
                }
            }

            val body = if (collectBody) buildBody(bodyLines ?: emptyList()) else null
            val shouldContinue = onMessage(messageCounter, envelope, headers, body, attachmentHint)
            if (!shouldContinue) break@mainLoop

            if (reachedEOF && nextEnvelope == null) {
                break@mainLoop
            }
        }
    }
}

private fun collectSummaries(source: MailboxSource): List<EmailSummary> {
    val summaries = mutableListOf<EmailSummary>()
    iterateMessages(source, needsBody = { false }) { index, envelope, headers, _, attachmentHint ->
        val senderFallback = envelope.defaultSender()
        val from = headers.firstHeaderValue("From") ?: senderFallback
        val subject = headers.firstHeaderValue("Subject") ?: "(no subject)"
        val date = headers.firstHeaderValue("Date") ?: "(no date)"
        summaries += EmailSummary(index, envelope, from, subject, date, attachmentHint)
        true
    }
    return summaries
}

private data class MessageDetailResult(val detail: MessageDetail?, val totalMessages: Int)

private fun loadMessageDetail(source: MailboxSource, targetIndex: Int): MessageDetailResult {
    val session = Session.getDefaultInstance(Properties())
    source.openReader().use { reader ->
        var nextEnvelope: String? = null
        var index = 0
        var capturedDetail: MessageDetail? = null

        while (true) {
            val envelopeLine = nextEnvelope ?: reader.readLine() ?: break
            nextEnvelope = null
            if (!envelopeLine.startsWith("From ")) {
                continue
            }

            index++
            val isTarget = index == targetIndex
            var reachedEOF = false
            var line: String?

            val headerLines = if (isTarget) mutableListOf<String>() else null
            val rawBuilder = if (isTarget) StringBuilder() else null

            while (true) {
                line = reader.readLine()
                if (line == null) {
                    reachedEOF = true
                    break
                }
                if (line.isEmpty()) {
                    if (isTarget) {
                        rawBuilder?.append("\r\n")
                    }
                    break
                }
                if (isTarget) {
                    headerLines?.add(line)
                    rawBuilder?.append(line)?.append("\r\n")
                }
            }

            val bodyLines = if (isTarget) mutableListOf<String>() else null
            if (!reachedEOF) {
                while (true) {
                    line = reader.readLine()
                    if (line == null) {
                        reachedEOF = true
                        break
                    }
                    if (line.startsWith("From ")) {
                        nextEnvelope = line
                        break
                    }
                    if (isTarget) {
                        rawBuilder?.append(line)?.append("\r\n")
                        bodyLines?.add(line)
                    }
                }
            }

            if (isTarget) {
                val headers = parseHeaders(headerLines ?: emptyList())
                val body = buildBody(bodyLines ?: emptyList())
                val email = EmailMessage(index, envelopeLine, headers, body)
                val rawBytes = (rawBuilder?.toString() ?: "").toByteArray(StandardCharsets.ISO_8859_1)
                val mimeMessage = MimeMessage(session, ByteArrayInputStream(rawBytes))
                val attachments = mutableListOf<AttachmentInfo>()
                collectAttachments(mimeMessage, attachments)
                val inlineImages = mutableMapOf<String, InlineImageContent>()
                collectInlineImages(mimeMessage, inlineImages)
                val preferredText = extractReadableText(mimeMessage) ?: email.body
                val htmlContent = extractHtmlContent(mimeMessage)
                capturedDetail = MessageDetail(
                    email,
                    mimeMessage,
                    attachments,
                    preferredText,
                    htmlContent,
                    inlineImages.toMap()
                )
            }

            if (reachedEOF && nextEnvelope == null) {
                break
            }
        }

        return MessageDetailResult(capturedDetail, index)
    }
}

private fun parseHeaders(headerLines: List<String>): Map<String, List<String>> {
    if (headerLines.isEmpty()) return emptyMap()

    val unfolded = mutableListOf<String>()
    for (line in headerLines) {
        if (line.startsWith(" ") || line.startsWith("\t")) {
            if (unfolded.isNotEmpty()) {
                unfolded[unfolded.lastIndex] = unfolded.last() + " " + line.trimStart()
            }
        } else {
            unfolded += line
        }
    }

    val result = linkedMapOf<String, MutableList<String>>()
    for (line in unfolded) {
        val colonIndex = line.indexOf(':')
        if (colonIndex <= 0) continue
        val key = line.substring(0, colonIndex).trim()
        val value = line.substring(colonIndex + 1).trim()
        if (key.isNotEmpty()) {
            result.getOrPut(key) { mutableListOf() }.add(value)
        }
    }
    return result.mapValues { it.value.toList() }
}

private fun buildBody(lines: List<String>): String {
    if (lines.isEmpty()) return ""
    return lines.joinToString("\n") { line ->
        when {
            line.startsWith(">From ") -> line.removePrefix(">")
            line == ">From" -> "From"
            else -> line
        }
    }
}

private fun collectAttachments(part: Part, attachments: MutableList<AttachmentInfo>) {
    when {
        part.isMimeType("multipart/*") -> {
            val multipart = part.content as Multipart
            for (i in 0 until multipart.count) {
                collectAttachments(multipart.getBodyPart(i), attachments)
            }
        }

        part.isMimeType("message/rfc822") -> {
            val nested = part.content
            if (nested is Part) {
                collectAttachments(nested, attachments)
            }
        }

        part is BodyPart -> {
            val disposition = part.disposition
            val decodedFileName = part.fileName?.let { decodeMimeText(it) }
            val shouldTreatAsAttachment =
                (disposition != null && disposition.equals(Part.ATTACHMENT, ignoreCase = true)) ||
                    (disposition != null && disposition.equals(Part.INLINE, ignoreCase = true) && !decodedFileName.isNullOrBlank()) ||
                    !decodedFileName.isNullOrBlank()
            if (shouldTreatAsAttachment) {
                val display = decodedFileName?.takeIf { it.isNotBlank() } ?: "attachment-${attachments.size + 1}"
                val mimeType = part.contentType.substringBefore(';').trim().ifBlank { "application/octet-stream" }
                val sizeBytes = part.size.takeIf { it >= 0 }?.toLong()
                attachments += AttachmentInfo(display, mimeType, sizeBytes, part)
            }
        }
    }
}

private fun collectInlineImages(part: Part, inlineImages: MutableMap<String, InlineImageContent>) {
    when {
        part.isMimeType("multipart/*") -> {
            val multipart = part.content as Multipart
            for (i in 0 until multipart.count) {
                collectInlineImages(multipart.getBodyPart(i), inlineImages)
            }
        }

        part.isMimeType("message/rfc822") -> {
            val nested = part.content
            if (nested is Part) {
                collectInlineImages(nested, inlineImages)
            }
        }

        else -> {
            val contentIdHeader = runCatching { part.getHeader("Content-ID")?.firstOrNull() }.getOrNull() ?: return
            val contentId = contentIdHeader.trim().trim('<', '>', '"', '\'')
            if (contentId.isEmpty()) return
            val normalizedId = contentId.lowercase(Locale.ROOT)
            if (inlineImages.containsKey(normalizedId)) return
            val mimeType = runCatching { part.contentType }.getOrNull()
                ?.substringBefore(';')?.trim().takeUnless { it.isNullOrBlank() }
                ?: "application/octet-stream"
            val bytes = runCatching { part.inputStream.use { it.readBytes() } }.getOrElse { return }
            inlineImages[normalizedId] = InlineImageContent(mimeType, bytes)
        }
    }
}

private fun decodeMimeText(value: String): String =
    try {
        MimeUtility.decodeText(value)
    } catch (_: Exception) {
        value
    }

private fun extractReadableText(part: Part): String? {
    return when {
        part.isMimeType("text/plain") -> part.readContentAsString()

        part.isMimeType("text/html") -> part.readContentAsString()?.let { stripHtmlTags(it) }

        part.isMimeType("multipart/alternative") -> {
            val multipart = part.content as Multipart
            var textPlain: String? = null
            var textHtml: String? = null
            for (i in 0 until multipart.count) {
                val bodyPart = multipart.getBodyPart(i)
                if (bodyPart.isMimeType("text/plain") && textPlain == null) {
                    textPlain = bodyPart.readContentAsString()
                } else if (bodyPart.isMimeType("text/html") && textHtml == null) {
                    textHtml = bodyPart.readContentAsString()?.let { stripHtmlTags(it) }
                }
            }
            textPlain ?: textHtml
        }

        part.isMimeType("multipart/*") -> {
            val multipart = part.content as Multipart
            for (i in 0 until multipart.count) {
                val result = extractReadableText(multipart.getBodyPart(i))
                if (!result.isNullOrBlank()) return result
            }
            null
        }

        part.isMimeType("message/rfc822") -> {
            val nested = part.content
            if (nested is Part) extractReadableText(nested) else null
        }

        else -> null
    }
}

private fun extractHtmlContent(part: Part): String? {
    return when {
        part.isMimeType("text/html") -> part.readContentAsString()

        part.isMimeType("multipart/alternative") -> {
            val multipart = part.content as Multipart
            var fallback: String? = null
            for (i in 0 until multipart.count) {
                val bodyPart = multipart.getBodyPart(i)
                if (bodyPart.isMimeType("text/html")) {
                    val html = bodyPart.readContentAsString()
                    if (!html.isNullOrBlank()) return html
                }
                if (fallback == null) {
                    fallback = extractHtmlContent(bodyPart)
                }
            }
            fallback
        }

        part.isMimeType("multipart/*") -> {
            val multipart = part.content as Multipart
            for (i in 0 until multipart.count) {
                val html = extractHtmlContent(multipart.getBodyPart(i))
                if (!html.isNullOrBlank()) return html
            }
            null
        }

        part.isMimeType("message/rfc822") -> {
            val nested = part.content
            if (nested is Part) extractHtmlContent(nested) else null
        }

        else -> null
    }
}

private fun Part.readContentAsString(): String? {
    val content = runCatching<Any?> { this.content }.getOrElse { return null }
    return when (content) {
        is String -> content
        is InputStream -> content.reader(guessCharset()).use { it.readText() }
        else -> content.toString()
    }
}

private fun Part.guessCharset(): Charset {
    val contentType = runCatching<String?> { this.contentType }.getOrNull()
    if (contentType != null) {
        val params = contentType.substringAfter(';', "").split(';')
        for (param in params) {
            val parts = param.split('=')
            if (parts.size == 2 && parts[0].trim().equals("charset", ignoreCase = true)) {
                return runCatching { Charset.forName(parts[1].trim().trim('"')) }.getOrDefault(StandardCharsets.UTF_8)
            }
        }
    }
    return StandardCharsets.UTF_8
}

private fun stripHtmlTags(html: String): String =
    html.replace(Regex("(?s)<head.*?</head>"), "")
        .replace(Regex("(?s)<style.*?</style>"), "")
        .replace(Regex("<br\\s*/?>", RegexOption.IGNORE_CASE), "\n")
        .replace(Regex("</p\\s*>", RegexOption.IGNORE_CASE), "\n\n")
        .replace(Regex("<[^>]+>"), "")
        .replace(Regex("&nbsp;"), " ")
        .replace(Regex("&amp;"), "&")
        .replace(Regex("&lt;"), "<")
        .replace(Regex("&gt;"), ">")
        .trim()

private fun ensureHtmlDocument(html: String): String {
    val hasHtml = html.contains("<html", ignoreCase = true)
    val hasBody = html.contains("<body", ignoreCase = true)
    return if (hasHtml || hasBody) html else "<html><body>$html</body></html>"
}

private fun plainTextToHtml(text: String): String {
    if (text.isEmpty()) return "<html><body style=\"font-family:monospace;\"></body></html>"
    val escaped = escapeForHtml(text)
    return "<html><body style=\"font-family:monospace; white-space: pre-wrap;\">$escaped</body></html>"
}

private fun escapeForHtml(value: String): String {
    val builder = StringBuilder(value.length)
    for (ch in value) {
        when (ch) {
            '<' -> builder.append("&lt;")
            '>' -> builder.append("&gt;")
            '&' -> builder.append("&amp;")
            '"' -> builder.append("&quot;")
            '\'' -> builder.append("&#39;")
            else -> builder.append(ch)
        }
    }
    return builder.toString()
}

private fun saveAttachment(info: AttachmentInfo, outputDir: Path): Path {
    if (!outputDir.exists()) {
        outputDir.createDirectories()
    }

    val sanitized = sanitizeFileName(info.displayName)
    val target = uniquePath(outputDir, sanitized)
    Files.newOutputStream(target, StandardOpenOption.CREATE_NEW).use { out ->
        info.bodyPart.inputStream.use { stream ->
            stream.copyTo(out)
        }
    }
    return target
}

private fun sanitizeFileName(name: String): String {
    val safe = name.replace(Regex("[\\\\/:*?\"<>|]"), "_").ifBlank { "attachment" }
    return safe.take(255)
}

private fun uniquePath(directory: Path, fileName: String): Path {
    var candidate = directory.resolve(fileName)
    if (!candidate.exists()) return candidate

    val base = fileName.substringBeforeLast('.', fileName)
    val ext = fileName.substringAfterLast('.', "")
    var counter = 1
    while (candidate.exists()) {
        val suffix = " ($counter)"
        val nextName = if (ext.isNotEmpty()) {
            "${base}${suffix}.$ext"
        } else {
            base + suffix
        }
        candidate = directory.resolve(nextName)
        counter++
    }
    return candidate
}

private fun formatSize(size: Long): String {
    if (size <= 0L) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    val magnitude = (Math.log10(size.toDouble()) / Math.log10(1024.0)).toInt().coerceAtMost(units.lastIndex)
    val scaled = size / Math.pow(1024.0, magnitude.toDouble())
    val formatter = DecimalFormat("#,##0.#")
    return "${formatter.format(scaled)} ${units[magnitude]}"
}

private fun printSummary(summaries: List<EmailSummary>, searchTerm: String?) {
    if (summaries.isEmpty()) {
        println("No messages found.")
        return
    }

    val filtered = searchTerm?.let { term ->
        val termLower = term.lowercase()
        summaries.filter { summary ->
            summary.subject.lowercase().contains(termLower) ||
                summary.from.lowercase().contains(termLower) ||
                summary.date.lowercase().contains(termLower)
        }
    } ?: summaries

    if (filtered.isEmpty()) {
        println("No messages matched the search term.")
        return
    }

    println("Entries: ${filtered.size} (of ${summaries.size})")
    println("Index | Date                          | From                           | Subject")
    println("----- | ----------------------------- | ------------------------------ | -------")
    for (summary in filtered) {
        println(
            "%4d  | %-28.28s | %-30.30s | %s".format(
                summary.index,
                summary.date.takeIf { it.isNotBlank() } ?: "(no date)",
                summary.from.takeIf { it.isNotBlank() } ?: "(unknown)",
                summary.subject.replace("\n", " ")
            )
        )
    }
}

private fun printMessage(source: MailboxSource, index: Int, includeHeaders: Boolean) {
    val (detail, total) = loadMessageDetail(source, index)
    val message = detail?.email
    if (message == null) {
        if (total == 0) {
            System.err.println("Message index $index is out of range; no messages detected in the file.")
        } else {
            System.err.println("Message index $index is out of range (1..$total).")
        }
        exitProcess(3)
    }

    println("Message #${message.index}")
    println("Envelope: ${message.envelopeFromLine}")
    println("From: ${message.fromLine}")
    println("Subject: ${message.subjectLine}")
    println("Date: ${message.dateLine}")

    if (includeHeaders && message.headers.isNotEmpty()) {
        println("\nHeaders:")
        for ((key, values) in message.headers) {
            for (value in values) {
                println("$key: $value")
            }
        }
    }

    println("\nBody:\n")
    println(detail.preferredText)

    if (detail.attachments.isNotEmpty()) {
        println("\nAttachments:")
        detail.attachments.forEachIndexed { idx, attachment ->
            val sizeText = attachment.sizeBytes?.let { formatSize(it) } ?: "unknown size"
            println("  ${idx + 1}. ${attachment.displayName} (${attachment.mimeType}, $sizeText)")
        }
    }
}

private fun launchGui(initialSelection: InitialSelection?) {
    EventQueue.invokeLater {
        try {
            javax.swing.UIManager.setLookAndFeel(javax.swing.UIManager.getSystemLookAndFeelClassName())
        } catch (_: Exception) {
        }
        val frame = MailboxViewerFrame()
        frame.isVisible = true
        frame.initialize(initialSelection)
    }
}

private class SwingBoxPane : JEditorPane() {
    private val swingBoxKit = SwingBoxEditorKit()
    private var htmlRenderWorker: SwingWorker<javax.swing.text.Document, Void>? = null
    private val imageWorkers = mutableMapOf<String, SwingWorker<ImageResource?, Void>>()
    private val loadedImages = mutableMapOf<String, ImageResource>()
    private val inlineImageResources = mutableMapOf<String, ImageResource>()
    private var remoteImages: Map<String, RemoteImage> = emptyMap()
    private var inlineImages: Map<String, InlineImageContent> = emptyMap()
    private var originalHtml: String = MINIMAL_HTML
    private var contentGeneration: Long = 0
    private var renderSequence: Long = 0

    var onRemoteImageLoadingStateChanged: ((Boolean) -> Unit)? = null

    init {
        editorKit = swingBoxKit
        contentType = swingBoxKit.contentType
        document = swingBoxKit.createDefaultDocument()
        isEditable = false
        (caret as? DefaultCaret)?.updatePolicy = DefaultCaret.ALWAYS_UPDATE
        showBlank()
    }

    fun showBlank() {
        contentGeneration++
        htmlRenderWorker?.cancel(true)
        cancelImageWorkers()
        disposeImageResources()
        remoteImages = emptyMap()
        inlineImages = emptyMap()
        originalHtml = MINIMAL_HTML
        renderHtmlAsync(MINIMAL_HTML, contentGeneration)
        notifyLoadingStateChanged(false, contentGeneration)
    }

    fun displayHtml(rawHtml: String, inlineImageData: Map<String, InlineImageContent>) {
        contentGeneration++
        htmlRenderWorker?.cancel(true)
        cancelImageWorkers()
        disposeImageResources()
        inlineImages = inlineImageData

        originalHtml = ensureHtmlDocument(rawHtml)
        remoteImages = extractRemoteImages(originalHtml)
        val generation = contentGeneration
        val displayHtml = buildDisplayHtml()
        renderHtmlAsync(displayHtml, generation)

        if (remoteImages.isEmpty()) {
            notifyLoadingStateChanged(false, generation)
        } else {
            startImageFetchers(generation)
        }
    }

    fun hasPendingRemoteImages(): Boolean =
        remoteImages.isNotEmpty() && remoteImages.keys.any { !loadedImages.containsKey(it) }

    private fun extractRemoteImages(html: String): Map<String, RemoteImage> {
        if (html.isBlank()) return emptyMap()
        val result = linkedMapOf<String, RemoteImage>()
        IMG_SRC_PATTERN.findAll(html).forEach { match ->
            val rawSrc = match.groupValues[3]
            val fetchUrl = normalizeRemoteSrc(rawSrc)
            if (fetchUrl != null && !result.containsKey(rawSrc)) {
                result[rawSrc] = RemoteImage(rawSrc, fetchUrl)
            }
        }
        return result
    }

    private fun normalizeRemoteSrc(value: String): String? {
        val trimmed = value.trim()
        return when {
            trimmed.startsWith("http://", ignoreCase = true) || trimmed.startsWith("https://", ignoreCase = true) -> trimmed
            trimmed.startsWith("//") -> "https:$trimmed"
            else -> null
        }
    }

    private fun normalizeCidSrc(value: String): String? {
        val trimmed = value.trim()
        if (!trimmed.startsWith("cid:", ignoreCase = true)) return null
        val cid = trimmed.substringAfter(':').trim().trim('<', '>', '"', '\'')
        if (cid.isEmpty()) return null
        return cid.lowercase(Locale.ROOT)
    }

    private fun buildDisplayHtml(): String {
        val source = originalHtml
        if (source.isBlank()) return MINIMAL_HTML
        return IMG_SRC_PATTERN.replace(source) { match ->
            val prefix = match.groupValues[1]
            val quote = match.groupValues[2]
            val rawSrc = match.groupValues[3]
            val cidKey = normalizeCidSrc(rawSrc)
            val replacement = when {
                cidKey != null -> ensureInlineImageResource(cidKey)?.src ?: TRANSPARENT_PLACEHOLDER.src
                remoteImages.containsKey(rawSrc) -> {
                    val remote = remoteImages.getValue(rawSrc)
                    loadedImages[remote.originalSrc]?.src ?: TRANSPARENT_PLACEHOLDER.src
                }
                else -> rawSrc
            }
            "$prefix$quote$replacement$quote"
        }
    }

    private fun renderHtmlAsync(html: String, generation: Long) {
        val renderToken = ++renderSequence
        htmlRenderWorker?.cancel(true)
        val worker = object : SwingWorker<javax.swing.text.Document, Void>() {
            override fun doInBackground(): javax.swing.text.Document {
                val document = swingBoxKit.createDefaultDocument()
                StringReader(html).use { reader ->
                    synchronized(swingBoxKit) {
                        swingBoxKit.read(reader, document, 0)
                    }
                }
                return document
            }

            override fun done() {
                if (isCancelled || generation != contentGeneration || renderToken != renderSequence) return
                runCatching { get() }
                    .onSuccess { doc ->
                        document = doc
                        caretPosition = 0
                    }
                    .onFailure { error ->
                        System.err.println("Failed to render HTML content: ${error.message}")
                    }
            }
        }
        htmlRenderWorker = worker
        worker.execute()
    }

    private fun startImageFetchers(generation: Long) {
        if (remoteImages.isEmpty()) {
            notifyLoadingStateChanged(false, generation)
            return
        }
        for ((originalSrc, remote) in remoteImages) {
            if (loadedImages.containsKey(originalSrc)) continue
            val worker = object : SwingWorker<ImageResource?, Void>() {
                override fun doInBackground(): ImageResource? {
                    return fetchRemoteImage(remote.fetchUrl)
                }

                override fun done() {
                    imageWorkers.remove(originalSrc)
                    val resource = runCatching { get() }.getOrNull()
                    if (generation != contentGeneration) {
                        resource?.dispose()
                        notifyLoadingStateChanged(hasPendingRemoteImages(), contentGeneration)
                        return
                    }
                    if (isCancelled) {
                        resource?.dispose()
                        notifyLoadingStateChanged(hasPendingRemoteImages(), generation)
                        return
                    }
                    if (resource != null) {
                        loadedImages.put(originalSrc, resource)?.dispose()
                        val updatedHtml = buildDisplayHtml()
                        renderHtmlAsync(updatedHtml, generation)
                    } else {
                        loadedImages.putIfAbsent(originalSrc, TRANSPARENT_PLACEHOLDER)
                    }
                    notifyLoadingStateChanged(hasPendingRemoteImages(), generation)
                }
            }
            imageWorkers[originalSrc] = worker
            worker.execute()
        }
        notifyLoadingStateChanged(true, generation)
    }

    private fun cancelImageWorkers() {
        if (imageWorkers.isEmpty()) return
        imageWorkers.values.forEach { it.cancel(true) }
        imageWorkers.clear()
    }

    private fun fetchRemoteImage(urlString: String): ImageResource? {
        return try {
            val url = URL(urlString)
            val connection = url.openConnection().apply {
                connectTimeout = 5_000
                readTimeout = 8_000
            }
            val bytes = connection.getInputStream().use { input ->
                input.readBytes()
            }
            val explicitType = connection.contentType?.takeIf { it.isNotBlank() }
            if (connection is HttpURLConnection) {
                connection.disconnect()
            }
            val detectedType = explicitType
                ?: URLConnection.guessContentTypeFromStream(bytes.inputStream())
                ?: URLConnection.guessContentTypeFromName(url.path)
                ?: "application/octet-stream"
            createTempImageFile(bytes, detectedType)
        } catch (_: Exception) {
            null
        }
    }

    private fun ensureInlineImageResource(contentId: String): ImageResource? {
        inlineImageResources[contentId]?.let { return it }
        val inline = inlineImages[contentId] ?: return null
        val resource = createTempImageFile(inline.data, inline.mimeType) ?: return null
        inlineImageResources[contentId] = resource
        return resource
    }

    private fun createTempImageFile(bytes: ByteArray, mimeType: String): ImageResource? {
        return runCatching {
            val extension = mimeTypeToExtension(mimeType)
            val tempFile = createTempFile("mbox-img-", extension)
            Files.newOutputStream(tempFile, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE).use { out ->
                out.write(bytes)
            }
            tempFile.toFile().deleteOnExit()
            ImageResource(tempFile.toUri().toString(), tempFile)
        }.getOrNull()
    }

    private fun mimeTypeToExtension(mimeType: String): String {
        val lower = mimeType.lowercase(Locale.ROOT)
        return when {
            lower == "image/jpeg" || lower == "image/jpg" -> ".jpg"
            lower == "image/png" -> ".png"
            lower == "image/gif" -> ".gif"
            lower == "image/bmp" -> ".bmp"
            lower == "image/webp" -> ".webp"
            lower == "image/svg+xml" -> ".svg"
            lower.startsWith("image/") -> {
                val raw = lower.substringAfter('/')
                val sanitized = raw.replace(Regex("[^a-z0-9]+"), "_")
                "." + sanitized.ifBlank { "img" }
            }
            else -> ".bin"
        }
    }

    private fun disposeImageResources() {
        loadedImages.values.forEach { it.dispose() }
        loadedImages.clear()
        inlineImageResources.values.forEach { it.dispose() }
        inlineImageResources.clear()
    }

    private fun notifyLoadingStateChanged(isLoading: Boolean, generation: Long) {
        SwingUtilities.invokeLater {
            if (generation == contentGeneration) {
                onRemoteImageLoadingStateChanged?.invoke(isLoading && hasPendingRemoteImages())
            }
        }
    }

    private data class ImageResource(val src: String, val file: Path?) {
        fun dispose() {
            val path = file ?: return
            runCatching { path.deleteIfExists() }
        }
    }

    private data class RemoteImage(val originalSrc: String, val fetchUrl: String)

    companion object {
        private const val TRANSPARENT_PIXEL_DATA_URI = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="
        private const val MINIMAL_HTML = "<html><body></body></html>"
        private val IMG_SRC_PATTERN = Regex("(?i)(<img\\b[^>]*?\\bsrc\\s*=\\s*)(['\"])(.*?)(\\2)")
        private val TRANSPARENT_PLACEHOLDER = ImageResource(TRANSPARENT_PIXEL_DATA_URI, null)
    }
}

private class MailboxViewerFrame : JFrame("MBOX Viewer") {
    private val summaryModel = DefaultListModel<EmailSummary>()
    private val messageList = JList(summaryModel).apply {
        selectionMode = ListSelectionModel.SINGLE_SELECTION
        cellRenderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: JList<*>,
                value: Any?,
                index: Int,
                isSelected: Boolean,
                cellHasFocus: Boolean
            ): java.awt.Component {
                val component = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
                if (component is JLabel && value is EmailSummary) {
                    val marker = if (value.hasAttachments) " 📎 " else "   "
                    component.text = "#${value.index}$marker${value.from} — ${value.subject}"
                }
                return component
            }
        }
        isEnabled = false
    }
    private val fromLabel = JLabel("From: ")
    private val subjectLabel = JLabel("Subject: ")
    private val dateLabel = JLabel("Date: ")
    private val bodyPane = SwingBoxPane().apply {
        isEditable = false
        contentType = "text/html"
    }
    private val attachmentsModel = DefaultListModel<AttachmentInfo>()
    private val attachmentsList = JList(attachmentsModel).apply {
        selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        cellRenderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: JList<*>,
                value: Any?,
                index: Int,
                isSelected: Boolean,
                cellHasFocus: Boolean
            ): java.awt.Component {
                val component = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
                if (component is JLabel && value is AttachmentInfo) {
                    component.text = value.toString()
                }
                return component
            }
        }
        addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(event: MouseEvent) {
                if (event.clickCount >= 2 && SwingUtilities.isLeftMouseButton(event)) {
                    val index = locationToIndex(event.point)
                    if (index < 0) return
                    val cellBounds = getCellBounds(index, index)
                    if (cellBounds == null || !cellBounds.contains(event.point)) return
                    val info = attachmentsModel.getElementAt(index)
                    selectedIndex = index
                    openAttachmentExternally(info)
                }
            }
        })
    }
    private val saveSelectedButton = JButton("Save Selected").apply { isEnabled = false }
    private val saveAllButton = JButton("Save All").apply { isEnabled = false }
    private val statusLabel = JLabel("No file loaded. Use File > Open.")
    private var lastViewedMessageIndex: Int? = null
    private var currentSource: MailboxSource? = null
    private var lastDirectory: Path? = null
    private val passwordCache = mutableMapOf<Path, CharArray>()

    @Volatile
    private var currentDetail: MessageDetail? = null

    @Volatile
    private var detailWorker: SwingWorker<MessageDetail?, Void>? = null

    @Volatile
    private var summaryWorker: SwingWorker<List<EmailSummary>, Void>? = null

    init {
        defaultCloseOperation = DO_NOTHING_ON_CLOSE
        addWindowListener(object : WindowAdapter() {
            override fun windowClosing(event: WindowEvent?) {
                exitApplication()
            }
        })
        minimumSize = Dimension(960, 640)
        layout = BorderLayout()
        jMenuBar = buildMenuBar()

        val headerPanel = JPanel().apply {
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
            add(subjectLabel)
            add(fromLabel)
            add(dateLabel)
        }
        val bodyScroll = JScrollPane(bodyPane)
        val attachmentsPanel = JPanel().apply {
            layout = BorderLayout(8, 8)
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
            add(JLabel("Attachments:"), BorderLayout.NORTH)
            add(JScrollPane(attachmentsList), BorderLayout.CENTER)
            val buttons = JPanel().apply {
                layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.X_AXIS)
                add(saveSelectedButton)
                add(javax.swing.Box.createHorizontalStrut(8))
                add(saveAllButton)
            }
            add(buttons, BorderLayout.SOUTH)
        }
        val leftPanel = JScrollPane(messageList)
        val rightPanel = JPanel(BorderLayout()).apply {
            add(headerPanel, BorderLayout.NORTH)
            add(bodyScroll, BorderLayout.CENTER)
            add(attachmentsPanel, BorderLayout.SOUTH)
        }
        val splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel).apply {
            resizeWeight = 0.3
        }
        add(splitPane, BorderLayout.CENTER)
        add(statusLabel.apply { border = BorderFactory.createEmptyBorder(4, 8, 4, 8) }, BorderLayout.SOUTH)

        messageList.addListSelectionListener { event ->
            if (!event.valueIsAdjusting) {
                loadSelectedMessage()
            }
        }

        saveSelectedButton.addActionListener {
            val selected = attachmentsList.selectedValuesList?.toList().orEmpty()
            if (selected.isEmpty()) {
                JOptionPane.showMessageDialog(
                    this,
                    "Select one or more attachments first.",
                    "No Attachments Selected",
                    JOptionPane.INFORMATION_MESSAGE
                )
            } else {
                saveAttachments(selected)
            }
        }

        saveAllButton.addActionListener {
            val all = (0 until attachmentsModel.size()).map { attachmentsModel.getElementAt(it) }
            if (all.isEmpty()) {
                JOptionPane.showMessageDialog(
                    this,
                    "No attachments available for this message.",
                    "Nothing to Save",
                    JOptionPane.INFORMATION_MESSAGE
                )
            } else {
                saveAttachments(all)
            }
        }

        bodyPane.onRemoteImageLoadingStateChanged = { loading ->
            val currentIndex = currentDetail?.email?.index
            val lastIndex = lastViewedMessageIndex
            if (currentIndex != null && lastIndex != null && currentIndex == lastIndex) {
                statusLabel.text = viewingStatusText(currentIndex, loading)
            }
        }
    }

    fun initialize(initialSelection: InitialSelection?) {
        if (initialSelection != null) {
            openSelectedPath(initialSelection.path, initialSelection.password?.copyOf())
        } else {
            SwingUtilities.invokeLater { promptForMbox(initialPrompt = true) }
        }
    }

    private fun buildMenuBar(): JMenuBar {
        val shortcutMask = runCatching { Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx }
            .getOrElse { InputEvent.CTRL_DOWN_MASK }
        return JMenuBar().apply {
            add(JMenu("File").apply {
                val openItem = JMenuItem("Open...").apply {
                    accelerator = KeyStroke.getKeyStroke(KeyEvent.VK_O, shortcutMask)
                    addActionListener { promptForMbox(initialPrompt = false) }
                }
                add(openItem)
                addSeparator()
                val exitItem = JMenuItem("Exit").apply {
                    accelerator = KeyStroke.getKeyStroke(KeyEvent.VK_Q, shortcutMask)
                    addActionListener { exitApplication() }
                }
                add(exitItem)
            })
        }
    }

    private fun exitApplication() {
        summaryWorker?.cancel(true)
        detailWorker?.cancel(true)
        dispose()
        exitProcess(0)
    }

    private fun promptForMbox(initialPrompt: Boolean) {
        val chooser = JFileChooser().apply {
            dialogTitle = "Select Mailbox File"
            fileSelectionMode = JFileChooser.FILES_ONLY
            isAcceptAllFileFilterUsed = true
            fileFilter = FileNameExtensionFilter("Mailbox files (*.mbox, *.7z, *.eml)", "mbox", "mbx", "mboxrd", "eml", "7z")
            val candidate = currentSource?.sourcePath?.parent ?: lastDirectory
            if (candidate != null && candidate.exists() && candidate.isDirectory()) {
                currentDirectory = candidate.toFile()
            }
        }
        val result = chooser.showOpenDialog(this)
        if (result == JFileChooser.APPROVE_OPTION) {
            val selectedPath = chooser.selectedFile.toPath()
            lastDirectory = selectedPath.parent
            openSelectedPath(selectedPath, passwordCache[selectedPath]?.copyOf())
        } else if (initialPrompt) {
            statusLabel.text = "Select File > Open to choose an mbox file."
        }
    }

    private fun openSelectedPath(path: Path, initialPassword: CharArray?) {
        if (!path.exists() || !path.isRegularFile()) {
            JOptionPane.showMessageDialog(
                this,
                "Selected file is not a valid mailbox: $path",
                "Invalid File",
                JOptionPane.ERROR_MESSAGE
            )
            return
        }

        var attemptPassword = initialPassword
        while (true) {
            val source = try {
                openMailboxSource(path, attemptPassword)
            } catch (ex: MailboxPasswordException) {
                val nextPassword = promptForPassword(path, ex.reason)
                if (nextPassword == null) {
                    if (currentSource == null) {
                        statusLabel.text = "Password required to open archive."
                    }
                    return
                }
                attemptPassword = nextPassword
                continue
            } catch (ex: MailboxFormatException) {
                val message = ex.message ?: "Failed to load ${path.name}."
                statusLabel.text = message
                JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE)
                return
            } catch (ex: Exception) {
                val message = ex.message ?: "Failed to load ${path.name}."
                statusLabel.text = message
                JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE)
                return
            }

            handleSourceLoaded(path, source, attemptPassword)
            return
        }
    }

    private fun handleSourceLoaded(path: Path, source: MailboxSource, password: CharArray?) {
        summaryWorker?.cancel(true)
        detailWorker?.cancel(true)
        currentSource = source
        currentDetail = null
        if (password != null) {
            passwordCache[path] = password.copyOf()
        } else {
            passwordCache.remove(path)
        }
        lastDirectory = path.parent
        title = "MBOX Viewer — ${source.displayName}"
        summaryModel.clear()
        attachmentsModel.clear()
        messageList.clearSelection()
        messageList.isEnabled = false
        updateDetail(null)
        statusLabel.text = "Loading messages from ${source.displayName}..."
        loadSummariesFor(source)
    }

    private fun loadSummariesFor(source: MailboxSource) {
        val activeSource = source
        summaryWorker?.cancel(true)
        detailWorker?.cancel(true)
        summaryWorker = object : SwingWorker<List<EmailSummary>, Void>() {
            override fun doInBackground(): List<EmailSummary> = collectSummaries(activeSource)

            override fun done() {
                if (isCancelled || currentSource !== activeSource) return
                summaryWorker = null
                runCatching { get() }
                    .onSuccess { summaries ->
                        summaryModel.clear()
                        summaries.forEach(summaryModel::addElement)
                        if (summaries.isNotEmpty()) {
                            messageList.isEnabled = true
                            messageList.selectedIndex = 0
                            statusLabel.text = "Loaded ${summaries.size} messages from ${activeSource.displayName}"
                        } else {
                            messageList.isEnabled = false
                            statusLabel.text = "No messages found in ${activeSource.displayName}"
                            updateDetail(null)
                        }
                    }
                    .onFailure { error ->
                        summaryModel.clear()
                        messageList.isEnabled = false
                        statusLabel.text = "Failed to load summaries: ${error.message}"
                        JOptionPane.showMessageDialog(
                            this@MailboxViewerFrame,
                            "Failed to load summaries:\n${error.message}",
                            "Error",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
            }
        }.also { it.execute() }
    }

    private fun loadSelectedMessage() {
        val source = currentSource ?: return
        val selected = messageList.selectedValue ?: run {
            updateDetail(null)
            return
        }
        detailWorker?.cancel(true)
        lastViewedMessageIndex = null
        statusLabel.text = "Loading message #${selected.index}..."
        detailWorker = object : SwingWorker<MessageDetail?, Void>() {
            override fun doInBackground(): MessageDetail? {
                if (isCancelled) return null
                val result = loadMessageDetail(source, selected.index)
                return result.detail
            }

            override fun done() {
                if (isCancelled || currentSource !== source) return
                detailWorker = null
                runCatching { get() }
                    .onSuccess { detail ->
                        updateDetail(detail)
                        if (detail == null) {
                            statusLabel.text = "No content available for message #${selected.index}"
                        }
                    }
                    .onFailure { error ->
                        updateDetail(null)
                        statusLabel.text = "Failed to load message: ${error.message}"
                        JOptionPane.showMessageDialog(
                            this@MailboxViewerFrame,
                            "Failed to load message:\n${error.message}",
                            "Error",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
            }
        }.also { it.execute() }
    }

    private fun promptForPassword(path: Path, reason: PasswordFailureReason): CharArray? {
        val passwordField = JPasswordField()
        val message = when (reason) {
            PasswordFailureReason.REQUIRED -> "Enter password for ${path.fileName}:"
            PasswordFailureReason.INVALID -> "Incorrect password. Try again for ${path.fileName}:"
        }
        val result = JOptionPane.showConfirmDialog(
            this,
            arrayOf(JLabel(message), passwordField),
            "Password Required",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        )
        return if (result == JOptionPane.OK_OPTION) passwordField.password else null
    }

    private fun updateDetail(detail: MessageDetail?) {
        currentDetail = detail
        if (detail == null) {
            subjectLabel.text = "Subject: "
            fromLabel.text = "From: "
            dateLabel.text = "Date: "
            bodyPane.showBlank()
            attachmentsModel.clear()
            saveSelectedButton.isEnabled = false
            saveAllButton.isEnabled = false
            lastViewedMessageIndex = null
            return
        }

        subjectLabel.text = "Subject: ${detail.email.subjectLine}"
        fromLabel.text = "From: ${detail.email.fromLine}"
        dateLabel.text = "Date: ${detail.email.dateLine}"
        val html = detail.htmlContent?.let(::ensureHtmlDocument) ?: plainTextToHtml(detail.preferredText)
        bodyPane.displayHtml(html, detail.inlineImages)

        attachmentsModel.clear()
        detail.attachments.forEach(attachmentsModel::addElement)
        val hasAttachments = detail.attachments.isNotEmpty()
        saveSelectedButton.isEnabled = hasAttachments
        saveAllButton.isEnabled = hasAttachments
        updateSummaryAttachmentFlag(detail.email.index, hasAttachments)
        updateViewingStatus(detail.email.index)
    }

    private fun updateViewingStatus(messageIndex: Int) {
        lastViewedMessageIndex = messageIndex
        statusLabel.text = viewingStatusText(messageIndex, bodyPane.hasPendingRemoteImages())
    }

    private fun updateSummaryAttachmentFlag(messageIndex: Int, hasAttachments: Boolean) {
        for (i in 0 until summaryModel.size()) {
            val summary = summaryModel.getElementAt(i)
            if (summary.index == messageIndex && summary.hasAttachments != hasAttachments) {
                summaryModel.set(i, summary.copy(hasAttachments = hasAttachments))
                break
            }
        }
    }

    private fun viewingStatusText(messageIndex: Int, loading: Boolean): String {
        return if (loading) {
            "Viewing message #${messageIndex} (loading remote images...)"
        } else {
            "Viewing message #${messageIndex}"
        }
    }

    private fun saveAttachments(attachments: List<AttachmentInfo>) {
        if (attachments.isEmpty()) return
        val chooser = JFileChooser().apply {
            dialogTitle = "Choose destination folder"
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            isAcceptAllFileFilterUsed = false
            val suggestedDir = lastDirectory ?: currentSource?.sourcePath?.parent
            if (suggestedDir != null && suggestedDir.exists() && suggestedDir.isDirectory()) {
                currentDirectory = suggestedDir.toFile()
            }
        }
        val result = chooser.showSaveDialog(this)
        if (result != JFileChooser.APPROVE_OPTION) return

        val directory = chooser.selectedFile.toPath()
        statusLabel.text = "Saving ${attachments.size} attachment(s)..."

        object : SwingWorker<List<Path>, Void>() {
            override fun doInBackground(): List<Path> {
                if (!directory.exists()) {
                    directory.createDirectories()
                } else if (!directory.isDirectory()) {
                    throw IllegalStateException("Selected destination is not a directory.")
                }
                val saved = mutableListOf<Path>()
                for (info in attachments) {
                    if (isCancelled) break
                    saved.add(saveAttachment(info, directory))
                }
                return saved
            }

            override fun done() {
                runCatching { get() }
                    .onSuccess { saved ->
                        lastDirectory = directory
                        statusLabel.text = "Saved ${saved.size} attachment(s) to ${directory.toAbsolutePath()}"
                        JOptionPane.showMessageDialog(
                            this@MailboxViewerFrame,
                            "Saved ${saved.size} attachment(s) to:\n${directory.toAbsolutePath()}",
                            "Attachments Saved",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    }
                    .onFailure { error ->
                        statusLabel.text = "Failed to save attachments: ${error.message}"
                        JOptionPane.showMessageDialog(
                            this@MailboxViewerFrame,
                            "Failed to save attachments:\n${error.message}",
                            "Error",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
            }
        }.execute()
    }

    private fun openAttachmentExternally(info: AttachmentInfo) {
        if (!Desktop.isDesktopSupported()) {
            JOptionPane.showMessageDialog(
                this,
                "Desktop integration is not supported on this platform.",
                "Open Attachment",
                JOptionPane.ERROR_MESSAGE
            )
            return
        }
        val desktop = try {
            Desktop.getDesktop()
        } catch (ex: Exception) {
            JOptionPane.showMessageDialog(
                this,
                "Desktop integration is unavailable: ${ex.message}",
                "Open Attachment",
                JOptionPane.ERROR_MESSAGE
            )
            return
        }
        if (!desktop.isSupported(Desktop.Action.OPEN)) {
            JOptionPane.showMessageDialog(
                this,
                "Opening files is not supported on this platform.",
                "Open Attachment",
                JOptionPane.ERROR_MESSAGE
            )
            return
        }

        statusLabel.text = "Opening ${info.displayName}..."
        object : SwingWorker<Path, Void>() {
            override fun doInBackground(): Path = extractAttachmentToTemp(info)

            override fun done() {
                runCatching { get() }
                    .onSuccess { tempPath ->
                        runCatching {
                            desktop.open(tempPath.toFile())
                        }.onSuccess {
                            statusLabel.text = "Opened ${info.displayName}"
                        }.onFailure { ex ->
                            statusLabel.text = "Failed to open ${info.displayName}: ${ex.message}"
                            JOptionPane.showMessageDialog(
                                this@MailboxViewerFrame,
                                "Unable to open ${info.displayName}:\n${ex.message}",
                                "Open Attachment",
                                JOptionPane.ERROR_MESSAGE
                            )
                        }
                    }
                    .onFailure { error ->
                        statusLabel.text = "Failed to extract ${info.displayName}: ${error.message}"
                        JOptionPane.showMessageDialog(
                            this@MailboxViewerFrame,
                            "Failed to extract ${info.displayName}:\n${error.message}",
                            "Open Attachment",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
            }
        }.execute()
    }

    private fun extractAttachmentToTemp(info: AttachmentInfo): Path {
        val sanitized = sanitizeFileName(info.displayName)
        val ext = sanitized.substringAfterLast('.', "")
        val base = sanitized.substringBeforeLast('.', sanitized).ifBlank { "attachment" }
        val baseFiltered = base.filter { it.isLetterOrDigit() }.ifBlank { "attachment" }
        val prefixRaw = "mbox-$baseFiltered"
        val prefix = prefixRaw.take(32).padEnd(3, 'x')
        val suffix = if (ext.isNotEmpty()) ".$ext" else ".bin"
        val tempFile = Files.createTempFile(prefix, suffix)
        Files.newOutputStream(tempFile).use { out ->
            info.bodyPart.inputStream.use { stream ->
                stream.copyTo(out)
            }
        }
        tempFile.toFile().deleteOnExit()
        return tempFile
    }
}



private fun mainImpl(rawArgs: Array<String>) {
    val options = parseArgs(rawArgs)
    when (options.mode) {
        RunMode.GUI -> {
            val selection = options.mboxPath?.let { InitialSelection(it, options.password) }
            launchGui(selection)
        }
        RunMode.CLI -> {
            val path = requireNotNull(options.mboxPath)
            val source = try {
                openMailboxSource(path, options.password)
            } catch (ex: MailboxPasswordException) {
                when (ex.reason) {
                    PasswordFailureReason.REQUIRED ->
                        System.err.println("Archive ${path.fileName} requires a password. Re-run with --password <value> or --password to enter it interactively.")
                    PasswordFailureReason.INVALID ->
                        System.err.println("Invalid password provided for archive ${path.fileName}.")
                }
                exitProcess(4)
            } catch (ex: MailboxFormatException) {
                System.err.println(ex.message ?: "Failed to load mailbox from ${path.fileName}.")
                exitProcess(5)
            } catch (ex: Exception) {
                System.err.println("Failed to load mailbox: ${ex.message}")
                exitProcess(5)
            }

            if (options.messageIndex != null) {
                printMessage(source, options.messageIndex, options.includeHeaders)
            } else {
                val summaries = collectSummaries(source)
                printSummary(summaries, options.searchTerm)
            }
        }
    }
}

mainImpl(args)
