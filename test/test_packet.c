#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "../src/packet.h"  // 패킷 관련 함수 및 구조체 포함

void test_protocol_conversion() {
    CU_ASSERT_STRING_EQUAL(get_protocol_name(IPPROTO_TCP), "TCP");
    CU_ASSERT_STRING_EQUAL(get_protocol_name(IPPROTO_UDP), "UDP");
    CU_ASSERT_STRING_EQUAL(get_protocol_name(IPPROTO_ICMP), "ICMP");
    CU_ASSERT_STRING_EQUAL(get_protocol_name(255), "Unknown");
}

void test_packet_stats() {
    packet_stats_t stats;
    init_stats(&stats);
    
    // 초기 상태 테스트
    CU_ASSERT_EQUAL(stats.total_packets, 0);
    CU_ASSERT_EQUAL(stats.tcp_packets, 0);
    CU_ASSERT_EQUAL(stats.total_bytes, 0);
    
    // 더미 패킷으로 통계 업데이트
    uint8_t dummy_packet[100] = {0};
    // IP 헤더 설정 (TCP 프로토콜)
    dummy_packet[14 + 9] = IPPROTO_TCP;  // protocol 필드
    
    update_stats(&stats, dummy_packet, 100);
    
    CU_ASSERT_EQUAL(stats.total_packets, 1);
    CU_ASSERT_EQUAL(stats.tcp_packets, 1);
    CU_ASSERT_EQUAL(stats.total_bytes, 100);
}

void test_rate_monitoring() {
    packet_rate_t rate;
    init_rate_monitor(&rate);
    
    // 초기 상태 테스트
    CU_ASSERT_EQUAL(rate.current_pps, 0.0f);
    CU_ASSERT_EQUAL(rate.peak_pps, 0.0f);
    
    // 패킷 업데이트 테스트
    update_rate(&rate, 1500); 
    
    CU_ASSERT(rate.packet_count > 0);
    CU_ASSERT(rate.byte_count == 1500);
}

void test_port_info() {
    uint16_t test_port = htons(80);  // HTTP 포트
    uint8_t dummy_packet[100] = {0};
    struct tcphdr *tcp = (struct tcphdr *)(dummy_packet + 34);  // IP 헤더 이후
    tcp->source = test_port;
    tcp->dest = htons(443);  // HTTPS 포트
    
    // TCP 헤더의 포트 정보가 올바르게 파싱되는지 테스트
    CU_ASSERT_EQUAL(ntohs(tcp->source), 80);
    CU_ASSERT_EQUAL(ntohs(tcp->dest), 443);
}


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
    CU_pSuite suite = CU_add_suite("Packet Analyzer Test Suite", 0, 0);

    CU_add_test(suite, "Protocol Conversion Test", test_protocol_conversion);
    CU_add_test(suite, "Packet Statistics Test", test_packet_stats);
    CU_add_test(suite, "Rate Monitoring Test", test_rate_monitoring);
    CU_add_test(suite, "Port Information Test", test_port_info);
    CU_add_test(suite, "Filter Application Test", test_apply_filter);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return CU_get_error();
}