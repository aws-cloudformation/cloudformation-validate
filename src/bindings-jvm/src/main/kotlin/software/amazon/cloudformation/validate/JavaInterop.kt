@file:JvmName("JavaInterop")

package software.amazon.cloudformation.validate

import software.amazon.cloudformation.validate.diagnostics.BudgetExhaustionRecord
import software.amazon.cloudformation.validate.diagnostics.Diagnostic
import software.amazon.cloudformation.validate.diagnostics.ReportMetadata
import software.amazon.cloudformation.validate.diagnostics.Summary
import software.amazon.cloudformation.validate.engine.AwsCliValue
import software.amazon.cloudformation.validate.rules.IdRange
import software.amazon.cloudformation.validate.templatemodel.ParameterInfo
import software.amazon.cloudformation.validate.templatemodel.SourceSpan

/*
 * Kotlin gives every member whose signature mentions UInt or ULong a mangled JVM name that Java
 * source cannot spell, so Java reads these fields through the signed views below.
 */

private const val UNSIGNED_32_MAX = 0xFFFF_FFFFL

fun Diagnostic.startLineAsLong(): Long? = startLine?.toLong()

fun Diagnostic.startColumnAsLong(): Long? = startColumn?.toLong()

fun Diagnostic.endLineAsLong(): Long? = endLine?.toLong()

fun Diagnostic.endColumnAsLong(): Long? = endColumn?.toLong()

fun Summary.fatalAsLong(): Long = fatal.toLong()

fun Summary.errorsAsLong(): Long = errors.toLong()

fun Summary.warningsAsLong(): Long = warnings.toLong()

fun Summary.informationalAsLong(): Long = informational.toLong()

fun Summary.debugAsLong(): Long = debug.toLong()

fun ReportMetadata.rulesEvaluatedAsLong(): Long = rulesEvaluated.toLong()

fun ReportMetadata.resourcesScannedAsLong(): Long = resourcesScanned.toLong()

fun ReportMetadata.suppressedAsLong(): Long = suppressed.toLong()

/** @throws ArithmeticException when the unsigned limit exceeds [Long.MAX_VALUE]. */
fun BudgetExhaustionRecord.limitAsLong(): Long = limit.toLongExact()

fun SourceSpan.startLineAsLong(): Long = startLine.toLong()

fun SourceSpan.startColumnAsLong(): Long = startColumn.toLong()

fun SourceSpan.endLineAsLong(): Long = endLine.toLong()

fun SourceSpan.endColumnAsLong(): Long = endColumn.toLong()

/** @throws ArithmeticException when the unsigned length exceeds [Long.MAX_VALUE]. */
fun ParameterInfo.minLengthAsLong(): Long? = minLength?.toLongExact()

/** @throws ArithmeticException when the unsigned length exceeds [Long.MAX_VALUE]. */
fun ParameterInfo.maxLengthAsLong(): Long? = maxLength?.toLongExact()

fun IdRange.startAsLong(): Long = start.toLong()

fun IdRange.endAsLong(): Long = end.toLong()

/** @throws ArithmeticException when the unsigned value exceeds [Long.MAX_VALUE]. */
fun AwsCliValue.UnsignedInteger.valueAsLong(): Long = value.toLongExact()

/**
 * Java cannot reach the [IdRange] constructor because its bounds are unsigned. Both bounds
 * must lie within 0..4294967295.
 *
 * @throws IllegalArgumentException when a bound lies outside that range.
 */
fun idRange(
    prefix: String,
    start: Long,
    end: Long,
): IdRange = IdRange(prefix = prefix, start = start.toUnsigned32("start"), end = end.toUnsigned32("end"))

private fun Long.toUnsigned32(boundName: String): UInt {
    require(this in 0..UNSIGNED_32_MAX) { "IdRange $boundName must be within 0..$UNSIGNED_32_MAX, got $this" }
    return toUInt()
}

private fun ULong.toLongExact(): Long {
    if (this > Long.MAX_VALUE.toULong()) {
        throw ArithmeticException("unsigned value $this exceeds Long.MAX_VALUE and has no signed long representation")
    }
    return toLong()
}
