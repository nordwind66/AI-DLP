/* Native-interface tests for libai_dlp: contract, error codes, memory ownership, threads, streaming. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_dlp.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

static dlp_engine_t *eng;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 200; i++) {
        dlp_result_t *r = NULL;
        const char *q = "{\"text\":\"tel 13800138000 mail a@b.co\",\"detectors\":[\"regex\"]}";
        int rc = dlp_sanitize(eng, q, strlen(q), &r);
        CHECK(rc == DLP_OK && r && strstr(r->data, "138****8000"));
        dlp_free_result(r);
    }
    return NULL;
}

int main(void) {
    dlp_result_t *r = NULL;
    CHECK(dlp_abi_version() == DLP_ABI_VERSION);
    const char *cfg = "{\"db_path\":\":memory:\",\"rules_dir\":\"rules\"}";
    CHECK(dlp_create(cfg, strlen(cfg), &eng, &r) == DLP_OK);
    CHECK(strstr(r->data, "capabilities") != NULL);
    dlp_free_result(r);

    /* contract: explicit lengths, no NUL needed */
    const char buf[] = "{\"text\":\"13800138000\"}GARBAGE";
    const size_t BL = sizeof("{\"text\":\"13800138000\"}") - 1;
    CHECK(dlp_detect(eng, buf, BL, &r) == DLP_OK);
    CHECK(strstr(r->data, "PHONE_NUMBER") && !strstr(r->data, "\"value\""));
    dlp_free_result(r);

    /* errors always produce valid JSON results and never crash */
    CHECK(dlp_detect(NULL, buf, BL, &r) == DLP_ERR_INVALID_ARG); CHECK(r && strstr(r->data, "error")); dlp_free_result(r);
    CHECK(dlp_detect(eng, NULL, 5, &r) == DLP_ERR_INVALID_ARG); dlp_free_result(r);
    CHECK(dlp_detect(eng, "{bad json", 9, &r) == DLP_ERR_INVALID_INPUT); dlp_free_result(r);
    const char badutf[] = {'{', '"', 't', 'e', 'x', 't', '"', ':', '"', (char)0xff, (char)0xfe, '"', '}'};
    CHECK(dlp_detect(eng, badutf, sizeof badutf, &r) == DLP_ERR_INVALID_INPUT); dlp_free_result(r);
    CHECK(dlp_detect(eng, buf, BL, NULL) == DLP_ERR_INVALID_ARG);
    const char *nopol = "{\"text\":\"x\",\"policy_id\":\"nope\"}";
    CHECK(dlp_detect(eng, nopol, strlen(nopol), &r) == DLP_ERR_NOT_FOUND); dlp_free_result(r);
    dlp_free_result(NULL); dlp_destroy(NULL);

    /* scenario H: real detection + sanitization */
    const char *h = "{\"text\":\"张三的手机号是13800138000。\",\"detectors\":[\"regex\"]}";
    CHECK(dlp_sanitize(eng, h, strlen(h), &r) == DLP_OK);
    CHECK(strstr(r->data, "[REDACTED_PERSON]的手机号是138****8000。"));
    dlp_free_result(r);

    /* private key => desensitized (whole PEM replaced by a fixed label), not refused */
    const char *k = "{\"text\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\\nVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\\n-----END RSA PRIVATE KEY-----\"}";
    CHECK(dlp_sanitize(eng, k, strlen(k), &r) == DLP_OK);
    CHECK(strstr(r->data, "\"decision\":\"modified\"") && strstr(r->data, "[REDACTED_PRIVATE_KEY]") && !strstr(r->data, "MIIEow"));
    dlp_free_result(r);

    /* tenant isolation of the vault through the ABI */
    const char *a = "{\"text\":\"联系人：王小明\",\"policy_id\":\"reversible\",\"session_id\":\"s1\",\"tenant_id\":\"A\",\"detectors\":[\"regex\"]}";
    CHECK(dlp_anonymize(eng, a, strlen(a), &r) == DLP_OK); CHECK(strstr(r->data, "[PERSON_1]")); dlp_free_result(r);
    const char *d1 = "{\"session_id\":\"s1\",\"tenant_id\":\"A\",\"text\":\"[PERSON_1]\",\"policy_id\":\"reversible\"}";
    const char *d2 = "{\"session_id\":\"s1\",\"tenant_id\":\"B\",\"text\":\"[PERSON_1]\",\"policy_id\":\"reversible\"}";
    CHECK(dlp_deanonymize(eng, d1, strlen(d1), &r) == DLP_OK); CHECK(strstr(r->data, "王小明")); dlp_free_result(r);
    CHECK(dlp_deanonymize(eng, d2, strlen(d2), &r) == DLP_ERR_NOT_FOUND); CHECK(!strstr(r->data, "王小明")); dlp_free_result(r);

    /* streaming: phone split over chunks, nothing before the verdict */
    dlp_stream_t *s = NULL;
    const char *so = "{\"policy_id\":\"default\",\"mode\":\"strict\"}";
    CHECK(dlp_stream_open(eng, so, strlen(so), &s, &r) == DLP_OK); dlp_free_result(r);
    const char *c1 = "data: call 138\n\ndata: 0013\n\n";
    CHECK(dlp_stream_push(s, (const uint8_t *)c1, strlen(c1), &r) == DLP_OK); CHECK(strstr(r->data, "\"output\":\"\"")); dlp_free_result(r);
    const char *c2 = "data: 8000\n\n";
    CHECK(dlp_stream_push(s, (const uint8_t *)c2, strlen(c2), &r) == DLP_OK); dlp_free_result(r);
    CHECK(dlp_stream_finish(s, &r) == DLP_OK); CHECK(strstr(r->data, "138****8000") && !strstr(r->data, "13800138000")); dlp_free_result(r);
    dlp_stream_close(s);

    /* thread safety */
    pthread_t t[8];
    for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);

    /* reload through the ABI */
    CHECK(dlp_reload_rules(eng, &r) == DLP_OK); CHECK(strstr(r->data, "\"changed\":false")); dlp_free_result(r);

    dlp_destroy(eng);
    puts("native ABI tests passed");
    return 0;
}
