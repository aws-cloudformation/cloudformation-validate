@file:JvmName("BindingsGson")

package software.amazon.cloudformation.validate.gson

import software.amazon.cloudformation.validate.diagnostics.ViolationContext
import software.amazon.cloudformation.validate.templatemodel.EntityType
import software.amazon.cloudformation.validate.templatemodel.JsonValueEnum
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import java.lang.reflect.Type

/**
 * Creates a [Gson] instance configured to serialize all UniFFI-generated bindings types
 * (UInt, JsonValueEnum, ViolationContext, EntityType) in a format matching the Rust serde output.
 */
fun buildBindingsGson(prettyPrinting: Boolean = false): Gson =
    GsonBuilder()
        .apply { if (prettyPrinting) setPrettyPrinting() }
        .registerTypeAdapter(UInt::class.java, UIntAdapter)
        .registerTypeAdapter(JsonValueEnum::class.java, JsonValueEnumAdapter)
        .registerTypeAdapter(ViolationContext::class.java, ViolationContextAdapter)
        .registerTypeAdapter(EntityType::class.java, EntityTypeAdapter)
        .create()

private object UIntAdapter : JsonSerializer<UInt> {
    override fun serialize(src: UInt, type: Type, ctx: JsonSerializationContext): JsonElement =
        JsonPrimitive(src.toLong())
}

private object EntityTypeAdapter : JsonSerializer<EntityType> {
    override fun serialize(src: EntityType, type: Type, ctx: JsonSerializationContext): JsonElement =
        JsonPrimitive(
            src.name.split('_').joinToString("") { part ->
                part.lowercase().replaceFirstChar { it.uppercase() }
            },
        )
}

private object JsonValueEnumAdapter : JsonSerializer<JsonValueEnum> {
    override fun serialize(src: JsonValueEnum, type: Type, ctx: JsonSerializationContext): JsonElement =
        when (src) {
            is JsonValueEnum.Null -> JsonNull.INSTANCE
            is JsonValueEnum.Bool -> JsonPrimitive(src.value)
            is JsonValueEnum.Int -> JsonPrimitive(src.value)
            is JsonValueEnum.Float -> JsonPrimitive(src.value)
            is JsonValueEnum.String -> JsonPrimitive(src.value)
            is JsonValueEnum.Array -> JsonArray().apply {
                src.items.forEach { add(serialize(it, type, ctx)) }
            }
            is JsonValueEnum.Object -> JsonObject().apply {
                src.entries.forEach { (k, v) -> add(k, serialize(v, type, ctx)) }
            }
        }
}

private object ViolationContextAdapter : JsonSerializer<ViolationContext> {
    override fun serialize(src: ViolationContext, type: Type, ctx: JsonSerializationContext): JsonElement =
        JsonObject().apply {
            src.actualValue?.let { add("actualValue", ctx.serialize(it, JsonValueEnum::class.java)) }
            src.expectedConstraint?.let { addProperty("expectedConstraint", it) }
            src.property?.let { addProperty("property", it) }
            src.lifecycle?.let { addProperty("lifecycle", it) }
            src.resolutionSource?.let { addProperty("resolutionSource", it) }
            src.extra?.let { extra ->
                add("extra", JsonObject().apply {
                    extra.forEach { (k, v) -> add(k, ctx.serialize(v, JsonValueEnum::class.java)) }
                })
            }
        }
}
