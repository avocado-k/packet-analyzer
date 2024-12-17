#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../src/packet.h"  // 패킷 관련 함수 및 구조체 포함

void test_apply_filter() {
    packet_filter_t filter;
    init_filter(&filter);
    set_filter(&filter, "192.168.1.1", "192.168.1.2", 80, 0);

    uint8_t packet[64] = { /* 패킷 데이터 초기화 */ };
    // 패킷 데이터 설정 (예: IP 헤더, TCP 헤더 등)

    CU_ASSERT(apply_filter(packet, &filter) == 1);  // 필터 조건에 맞는 경우
    set_filter(&filter, "10.0.0.1", NULL, 0, 0);
    CU_ASSERT(apply_filter(packet, &filter) == 0);  // 필터 조건에 맞지 않는 경우
}

int main() {
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("Packet Filter Suite", 0, 0);


    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return CU_get_error();
}
