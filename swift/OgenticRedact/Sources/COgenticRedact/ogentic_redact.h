/**
 * C ABI for on-device redaction. The built-in EMAIL/PHONE/US_SSN scanner is
 * a development convenience. This header is maintained with the Rust exports.
 * Every returned buffer must be freed with ogentic_redact_free(ptr, length).
 * Byte inputs use explicit UTF-8 lengths. NULL input is accepted only at length 0.
 * Handles must be closed exactly once; never close while another call uses them.
 */
#ifndef OGENTIC_REDACT_H
#define OGENTIC_REDACT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

const char *ogentic_redact_version(void); /* static: do not free */
void ogentic_redact_free(uint8_t *ptr, size_t len);

/* One-way JSON: {"text": string, "redaction_count": number}. No plaintext map. */
uint8_t *ogentic_redact(const uint8_t *input, size_t input_len, size_t *out_len);
uint8_t *ogentic_redact_with_salt(const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len, size_t *out_len);

/* Default restoration budgets: 16 MiB UTF-8 bytes and 100000 mapped occurrences.
 * Status: 0 success, 1 missing mapping, 2 limit exceeded, 3 invalid input, 4 allocation failure. */
#define OGENTIC_RESTORE_OK 0
#define OGENTIC_RESTORE_MAPPING_NOT_FOUND 1
#define OGENTIC_RESTORE_LIMIT_EXCEEDED 2
#define OGENTIC_RESTORE_INVALID_INPUT 3
#define OGENTIC_RESTORE_ALLOCATION_FAILED 4
/* Legacy explicit-map restoration with the default limits. */
uint8_t *ogentic_unredact(const uint8_t *input, size_t input_len,
    const uint8_t *token_map_json, size_t token_map_len, size_t *out_len);

/* Custom limits; zero permitted. Errors return NULL, length 0 and optional status. */
uint8_t *ogentic_unredact_with_limits(const uint8_t *input, size_t input_len,
    const uint8_t *token_map_json, size_t token_map_len, size_t max_output_bytes,
    size_t max_replacements, size_t *out_len, uint8_t *out_status);

/* Explicit reversible mode. Originals are scoped to an opaque in-process store. */
typedef struct OgenticRedactor OgenticRedactor;
OgenticRedactor *ogentic_redactor_open(void);
OgenticRedactor *ogentic_redactor_open_with_limits(size_t max_output_bytes, size_t max_replacements);
void ogentic_redactor_close(OgenticRedactor *handle);
/* JSON: {"text": string, "mapping_id": opaque string}, never an inline map. */
uint8_t *ogentic_redactor_redact(OgenticRedactor *handle,
    const uint8_t *input, size_t input_len, size_t *out_len);
/* Restore within session limits; NULL on error. Successful consume deletes the mapping. */
uint8_t *ogentic_redactor_unredact(OgenticRedactor *handle,
    const uint8_t *input, size_t input_len,
    const uint8_t *mapping_id, size_t mapping_id_len, uint8_t consume, size_t *out_len);
/* Same operation with explicit error status. Limit rejection never consumes. */
uint8_t *ogentic_redactor_unredact_with_status(OgenticRedactor *handle,
    const uint8_t *input, size_t input_len, const uint8_t *mapping_id,
    size_t mapping_id_len, uint8_t consume, size_t *out_len, uint8_t *out_status);
uint8_t ogentic_redactor_delete(OgenticRedactor *handle,
    const uint8_t *mapping_id, size_t mapping_id_len);

/* Batch sentence delivery: open redacts the entire input before returning.
 * next returns {"text": string}, preserving all separators and whitespace.
 * There are no retained plaintext maps. This is not incremental detection.
 * NULL/length 0 from next means exhausted. */
typedef struct OgenticRedactStream OgenticRedactStream;
OgenticRedactStream *ogentic_redact_stream_open(const uint8_t *input, size_t input_len);
uint8_t *ogentic_redact_stream_next(OgenticRedactStream *handle, size_t *out_len);
void ogentic_redact_stream_close(OgenticRedactStream *handle);
#ifdef __cplusplus
}
#endif
#endif
