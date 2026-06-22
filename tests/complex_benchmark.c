#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STAGE1_MAGIC 0xA5A5A5A5u

typedef struct {
    const char *name;
    uint32_t id;
    uint64_t value;
} Node;

static uint32_t g_seed = 0x12345678;
static int g_table[16] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53};

static uint32_t xorshift32(void) {
    g_seed ^= g_seed << 13;
    g_seed ^= g_seed >> 17;
    g_seed ^= g_seed << 5;
    return g_seed;
}

static uint64_t mix_u64(uint64_t v) {
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    v *= 0xc4ceb9fe1a85ec53ULL;
    v ^= v >> 33;
    return v;
}

static int analyze_string(const char *s) {
    int score = 0;
    for (size_t i = 0; s[i] != '\0'; i++) {
        if (isprint((unsigned char)s[i])) {
            score += 1;
        }
        score += (int)(s[i] & 0x0f);
    }
    return score;
}

static uint32_t crc32_like(const uint8_t *data, size_t n) {
    uint32_t crc = STAGE1_MAGIC;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = data[i] ^ (uint8_t)crc;
        crc ^= b * 0x9e3779b1u;
        crc = (crc << 5) | (crc >> 27);
    }
    return crc;
}

static int recursive_reduce(int x, int depth) {
    if (depth <= 0) {
        return x;
    }
    if (x == 0) {
        return x + 1;
    }
    if (x < 0) {
        return recursive_reduce(-x, depth - 1) + depth;
    }
    return recursive_reduce(x / 2, depth - 1) + recursive_reduce(x - 1, depth - 1) + 1;
}

static int compare_nodes(const void *a, const void *b) {
    const Node *na = (const Node *)a;
    const Node *nb = (const Node *)b;
    if (na->value < nb->value) return -1;
    if (na->value > nb->value) return 1;
    return (int)na->id - (int)nb->id;
}

static int populate_nodes(Node *nodes, size_t n) {
    int checksum = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t v = mix_u64(((uint64_t)i << 32) | xorshift32());
        nodes[i].id = (uint32_t)(i + 1);
        nodes[i].value = (v ^ 0xBEEFDEADuLL) & 0xffffffffu;
        nodes[i].name = (i % 2 == 0) ? "alpha" : "beta";

        checksum += (int)(nodes[i].value & 0xffff);
    }
    qsort(nodes, n, sizeof(Node), compare_nodes);
    return checksum;
}

static int compute_series(int base, int count, Node *out, size_t *out_n) {
    if (count <= 0 || out == NULL || out_n == NULL) {
        return -1;
    }

    int acc = 0;
    size_t n = (size_t)(count < 16 ? count : 16);
    for (size_t i = 0; i < n; i++) {
        uint64_t v = mix_u64((uint64_t)(base + (int)i) * 0x1234u + (uint64_t)g_table[i]);
        out[i].id = (uint32_t)(base + (int)i);
        out[i].value = v;
        out[i].name = (i % 3 == 0) ? "series_a" : ((i % 3 == 1) ? "series_b" : "series_c");
        acc += (int)(v & 0xff);
    }
    *out_n = n;
    return acc;
}

static void print_nodes(const Node *nodes, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("node[%zu] id=%u value=%llu name=%s\n", i, nodes[i].id,
               (unsigned long long)nodes[i].value, nodes[i].name);
    }
}

static void pipeline(const char *input) {
    Node primary[24];
    Node series[32];
    memset(primary, 0, sizeof(primary));
    memset(series, 0, sizeof(series));

    size_t n = sizeof(primary) / sizeof(primary[0]);
    int checksum = populate_nodes(primary, n);
    size_t n_series = 0;
    int series_score = compute_series((int)strlen(input), 24, series, &n_series);

    int len_score = analyze_string(input);
    uint32_t csum = crc32_like((const uint8_t *)input, strlen(input));
    int recursive = recursive_reduce((int)csum, 6);

    printf("input-len=%zu score=%d crc=0x%08x recursive=%d base-table=%d series=%d\n", strlen(input), len_score, csum,
           recursive, checksum, series_score);
    print_nodes(series, n_series);

    int64_t mix = 0;
    for (size_t i = 0; i < n; i++) {
        mix += (int64_t)primary[i].value;
    }
    for (size_t i = 0; i < n_series; i++) {
        mix ^= (int64_t)series[i].value;
    }

    if ((mix & 1) == 0) {
        puts("pipeline mode: even mix, extra branch");
    } else {
        puts("pipeline mode: odd mix, fallback branch");
    }
}

static int dispatch(int mode, const char *payload) {
    int result = 0;
    switch (mode) {
    case 0:
        result = analyze_string(payload);
        break;
    case 1:
        result = recursive_reduce((int)strlen(payload), 8);
        break;
    case 2:
        result = crc32_like((const uint8_t *)payload, strlen(payload)) & 0x7fffffff;
        break;
    default:
        result = analyze_string(payload) + recursive_reduce((int)strlen(payload), 4);
        break;
    }
    return result;
}

int main(int argc, char **argv) {
    g_seed ^= (uint32_t)time(NULL);
    char buf[256] = "rev_complex_payload";

    if (argc > 1) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    }

    const char *path = (argc > 2) ? argv[2] : ".";
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
    }

    int mode = (argc > 3) ? atoi(argv[3]) : (int)(strlen(buf) % 3);
    int score = dispatch(mode, buf);

    pipeline(buf);
    if (score > 0) {
        return score % 255;
    }
    return 0;
}
