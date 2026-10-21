/* Minimal C client: real detection + sanitization through libai_dlp. */
#include <stdio.h>
#include <string.h>
#include "ai_dlp.h"

static void print_field(const char *json, const char *key) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) { printf("%s: (none)\n", key); return; }
    p += strlen(pat);
    printf("%s: ", key);
    while (*p && !(*p == '"' && p[-1] != '\\')) putchar(*p++);
    putchar('\n');
}

int main(void) {
    const char *cfg = "{\"db_path\":\":memory:\",\"rules_dir\":\"rules\"}";
    dlp_engine_t *eng = NULL;
    dlp_result_t *res = NULL;
    int rc = dlp_create(cfg, strlen(cfg), &eng, &res);
    if (rc != DLP_OK) { fprintf(stderr, "create failed (%d): %s\n", rc, res ? res->data : "?"); dlp_free_result(res); return 1; }
    dlp_free_result(res);
    printf("libai_dlp %s (ABI %u)\n", dlp_version(), dlp_abi_version());

    const char *req = "{\"text\":\"张三的手机号是13800138000，key=AKIAZ3XQKVN5TLWM7EPD\",\"policy_id\":\"default\",\"detectors\":[\"regex\",\"secret\"]}";
    rc = dlp_sanitize(eng, req, strlen(req), &res);
    printf("sanitize rc=%d\n", rc);
    if (rc == DLP_OK) {
        print_field(res->data, "sanitized_text");
        print_field(res->data, "decision");
    }
    dlp_free_result(res);

    /* reversible round trip */
    const char *a = "{\"text\":\"联系人：李四，邮箱 lisi@example.com\",\"policy_id\":\"reversible\",\"session_id\":\"c-demo-1\",\"detectors\":[\"regex\"]}";
    if (dlp_anonymize(eng, a, strlen(a), &res) == DLP_OK) print_field(res->data, "sanitized_text");
    dlp_free_result(res);
    const char *d = "{\"session_id\":\"c-demo-1\",\"text\":\"已通知[PERSON_1]，邮件发往[EMAIL_ADDRESS_1]\",\"policy_id\":\"reversible\"}";
    if (dlp_deanonymize(eng, d, strlen(d), &res) == DLP_OK) print_field(res->data, "text");
    dlp_free_result(res);

    dlp_destroy(eng);
    return 0;
}
