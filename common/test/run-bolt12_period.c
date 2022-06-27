#include "config.h"
#include "../bolt12.c"
#include "../json.c"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <common/setup.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for amount_asset_is_main */
bool amount_asset_is_main(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_is_main called!\n"); abort(); }
/* Generated stub for amount_asset_to_sat */
struct amount_sat amount_asset_to_sat(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_to_sat called!\n"); abort(); }
/* Generated stub for amount_sat */
struct amount_sat amount_sat(u64 satoshis UNNEEDED)
{ fprintf(stderr, "amount_sat called!\n"); abort(); }
/* Generated stub for amount_sat_add */
 bool amount_sat_add(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_add called!\n"); abort(); }
/* Generated stub for amount_sat_eq */
bool amount_sat_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_eq called!\n"); abort(); }
/* Generated stub for amount_sat_greater_eq */
bool amount_sat_greater_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_greater_eq called!\n"); abort(); }
/* Generated stub for amount_sat_sub */
 bool amount_sat_sub(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_sub called!\n"); abort(); }
/* Generated stub for amount_sat_to_asset */
struct amount_asset amount_sat_to_asset(struct amount_sat *sat UNNEEDED, const u8 *asset UNNEEDED)
{ fprintf(stderr, "amount_sat_to_asset called!\n"); abort(); }
/* Generated stub for amount_tx_fee */
struct amount_sat amount_tx_fee(u32 fee_per_kw UNNEEDED, size_t weight UNNEEDED)
{ fprintf(stderr, "amount_tx_fee called!\n"); abort(); }
/* Generated stub for features_unsupported */
int features_unsupported(const struct feature_set *our_features UNNEEDED,
			 const u8 *their_features UNNEEDED,
			 enum feature_place p UNNEEDED)
{ fprintf(stderr, "features_unsupported called!\n"); abort(); }
/* Generated stub for from_bech32_charset */
bool from_bech32_charset(const tal_t *ctx UNNEEDED,
			 const char *bech32 UNNEEDED, size_t bech32_len UNNEEDED,
			 char **hrp UNNEEDED, u8 **data UNNEEDED)
{ fprintf(stderr, "from_bech32_charset called!\n"); abort(); }
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_bool */
bool fromwire_bool(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bool called!\n"); abort(); }
/* Generated stub for fromwire_fail */
void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_secp256k1_ecdsa_signature */
void fromwire_secp256k1_ecdsa_signature(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
					secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "fromwire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for fromwire_sha256 */
void fromwire_sha256(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "fromwire_sha256 called!\n"); abort(); }
/* Generated stub for fromwire_tal_arrn */
u8 *fromwire_tal_arrn(const tal_t *ctx UNNEEDED,
		       const u8 **cursor UNNEEDED, size_t *max UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_tal_arrn called!\n"); abort(); }
/* Generated stub for fromwire_tlv_invoice */
struct tlv_invoice *fromwire_tlv_invoice(const tal_t *ctx UNNEEDED,
						  const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_tlv_invoice called!\n"); abort(); }
/* Generated stub for fromwire_tlv_invoice_request */
struct tlv_invoice_request *fromwire_tlv_invoice_request(const tal_t *ctx UNNEEDED,
						  const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_tlv_invoice_request called!\n"); abort(); }
/* Generated stub for fromwire_tlv_offer */
struct tlv_offer *fromwire_tlv_offer(const tal_t *ctx UNNEEDED,
						  const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_tlv_offer called!\n"); abort(); }
/* Generated stub for fromwire_u32 */
u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }
/* Generated stub for fromwire_u64 */
u64 fromwire_u64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u64 called!\n"); abort(); }
/* Generated stub for fromwire_u8 */
u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }
/* Generated stub for fromwire_u8_array */
void fromwire_u8_array(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_u8_array called!\n"); abort(); }
/* Generated stub for json_add_member */
void json_add_member(struct json_stream *js UNNEEDED,
		     const char *fieldname UNNEEDED,
		     bool quote UNNEEDED,
		     const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "json_add_member called!\n"); abort(); }
/* Generated stub for json_member_direct */
char *json_member_direct(struct json_stream *js UNNEEDED,
			 const char *fieldname UNNEEDED, size_t extra UNNEEDED)
{ fprintf(stderr, "json_member_direct called!\n"); abort(); }
/* Generated stub for merkle_tlv */
void merkle_tlv(const struct tlv_field *fields UNNEEDED, struct sha256 *merkle UNNEEDED)
{ fprintf(stderr, "merkle_tlv called!\n"); abort(); }
/* Generated stub for sighash_from_merkle */
void sighash_from_merkle(const char *messagename UNNEEDED,
			 const char *fieldname UNNEEDED,
			 const struct sha256 *merkle UNNEEDED,
			 struct sha256 *sighash UNNEEDED)
{ fprintf(stderr, "sighash_from_merkle called!\n"); abort(); }
/* Generated stub for to_bech32_charset */
char *to_bech32_charset(const tal_t *ctx UNNEEDED,
			const char *hrp UNNEEDED, const u8 *data UNNEEDED)
{ fprintf(stderr, "to_bech32_charset called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_bool */
void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }
/* Generated stub for towire_secp256k1_ecdsa_signature */
void towire_secp256k1_ecdsa_signature(u8 **pptr UNNEEDED,
			      const secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "towire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_tlv_invoice */
void towire_tlv_invoice(u8 **pptr UNNEEDED, const struct tlv_invoice *record UNNEEDED)
{ fprintf(stderr, "towire_tlv_invoice called!\n"); abort(); }
/* Generated stub for towire_tlv_invoice_request */
void towire_tlv_invoice_request(u8 **pptr UNNEEDED, const struct tlv_invoice_request *record UNNEEDED)
{ fprintf(stderr, "towire_tlv_invoice_request called!\n"); abort(); }
/* Generated stub for towire_tlv_offer */
void towire_tlv_offer(u8 **pptr UNNEEDED, const struct tlv_offer *record UNNEEDED)
{ fprintf(stderr, "towire_tlv_offer called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_u8 */
void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

int main(int argc, char *argv[])
{
	char *json;
	size_t i;
	jsmn_parser parser;
	jsmntok_t toks[5000];
	const jsmntok_t *t;

	common_setup(argv[0]);

	if (argv[1])
		json = grab_file(tmpctx, argv[1]);
	else {
		char *dir = getenv("BOLTDIR");
		json = grab_file(tmpctx,
				 path_join(tmpctx,
					   dir ? dir : "../lightning-rfc",
					   "bolt12/offer-period-test.json"));
		if (!json) {
			printf("test file not found, skipping\n");
			common_shutdown();
			exit(0);
		}
	}

	jsmn_init(&parser);
	if (jsmn_parse(&parser, json, strlen(json), toks, ARRAY_SIZE(toks)) < 0)
		abort();

	/* We deal in UTC; mktime() uses local time */
	setenv("TZ", "", 1);
	json_for_each_arr(i, t, toks) {
		struct tlv_offer_recurrence recurrence;
		int unit;
		const jsmntok_t *exp;
		u64 base, secs, n;
		time_t time;
		char *timestring, *tstr, **tparts;

		assert(json_to_u64(json, json_get_member(json, t, "basetime"),
				   &base));
		assert(json_to_int(json, json_get_member(json, t, "time_unit"),
				   &unit));
		recurrence.time_unit = unit;
		json_to_u32(json, json_get_member(json, t, "period"),
			    &recurrence.period);
		assert(json_to_u64(json, json_get_member(json, t, "n"), &n));
		exp = json_get_member(json, t, "expect");
		assert(json_to_u64(json, json_get_member(json, exp, "seconds_since_epoch"),
				   &secs));
		timestring = json_strdup(tmpctx, json,
					 json_get_member(json, exp, "timestring"));
		time = secs;
		/* Form is 'Thu Dec 31 10:00:01 1970\n' */
		tstr = asctime(gmtime(&time));
		/* Remove \n */
		tstr[strlen(tstr)-1] = '\0';
		tparts = tal_strsplit(tmpctx, tstr, " ", STR_EMPTY_OK);
		/* Replace day */
		tparts[0] = "UTC";
		/* Now each part should appear. */
		for (size_t i = 0; tparts[i]; i++)
			assert(strstr(timestring, tparts[i]));
		assert(offer_period_start(base, n, &recurrence) == secs);
	}
	common_shutdown();
	return 0;
}
