// C++ client with RAII wrappers around the C ABI.
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include "ai_dlp.h"

struct ResultDeleter { void operator()(dlp_result_t *r) const { dlp_free_result(r); } };
using Result = std::unique_ptr<dlp_result_t, ResultDeleter>;

class Engine {
public:
    explicit Engine(const std::string &cfg) {
        dlp_result_t *r = nullptr;
        int rc = dlp_create(cfg.data(), cfg.size(), &h_, &r);
        Result guard(r);
        if (rc != DLP_OK) throw std::runtime_error(std::string("dlp_create: ") + (r ? r->data : "?"));
    }
    ~Engine() { dlp_destroy(h_); }
    Engine(const Engine &) = delete;
    Engine &operator=(const Engine &) = delete;

    // returns the JSON response; throws on a non-zero status (message = error JSON)
    std::string sanitize(const std::string &req) { return call(dlp_sanitize, req); }
    std::string detect(const std::string &req) { return call(dlp_detect, req); }

private:
    using Fn = int (*)(const dlp_engine_t *, const char *, size_t, dlp_result_t **);
    std::string call(Fn fn, const std::string &req) {
        dlp_result_t *r = nullptr;
        int rc = fn(h_, req.data(), req.size(), &r);
        Result guard(r);
        if (rc != DLP_OK) throw std::runtime_error(r ? r->data : "unknown error");
        return std::string(r->data, r->len);
    }
    dlp_engine_t *h_ = nullptr;
};

int main() {
    try {
        Engine e(R"({"db_path":":memory:","rules_dir":"rules"})");
        std::string out = e.sanitize(R"({"text":"Mail alice@example.com, card 4111 1111 1111 1111","policy_id":"default","detectors":["regex","secret"]})");
        auto p = out.find("\"sanitized_text\":\"");
        std::cout << (p == std::string::npos ? out : out.substr(p, out.find('"', p + 18) - p + 1)) << "\n";
    } catch (const std::exception &ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
