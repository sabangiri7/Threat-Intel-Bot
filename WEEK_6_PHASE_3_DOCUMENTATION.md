# Week 6 Phase 3.1 Implementation Documentation
## IOC Correlation Engine Development

**Project:** Threat Intelligence Bot for SOC Analysts  
**Phase:** Phase 3.1 - Correlation & Campaign Clustering  
**Timeline:** Week 6 (January 7–13, 2026)  
**Current Status:** Days 1-2 Complete ✅  
**Document Version:** 1.0  
**Last Updated:** January 7, 2026, 8:39 AM +0545

---

## EXECUTIVE SUMMARY

Phase 3.1 transforms the Threat Intelligence Bot from a **data enrichment tool** into an **actionable intelligence system**. After successfully enriching individual IOCs in Phase 2, the system now identifies relationships between IOCs and aggregates them into coherent threat campaigns.

**Completed Work (Days 1-2):**
- ✅ Rule 1 & Rule 2 Correlation Engine (9 tests passing)
- ✅ Severity Scoring System (12 tests passing)
- ✅ Total: 21 passing unit tests

---

## PART 1: DAY 1 - CORE RULES IMPLEMENTATION

### 1.1 Rule 1: Infrastructure Association

Groups IOCs sharing the same IP infrastructure within 48-hour time window.
- Time Window: 48 hours
- Minimum Group Size: 2 IOCs
- Complexity: O(n²)

### 1.2 Rule 2: Malware Family Clustering

Groups IOCs with same malware family within 72-hour time window.
- Time Window: 72 hours
- Minimum Group Size: 2 IOCs
- Complexity: O(n²)

### 1.3 Testing Results

**9 Unit Tests (All Passing):**
- test_rule_1_basic_grouping ✓
- test_rule_1_time_window ✓
- test_rule_2_basic_grouping ✓
- test_rule_2_multiple_families ✓
- test_parse_timestamp ✓
- test_is_within_time_window ✓
- test_extract_ips ✓
- test_merge_groups ✓
- test_full_pipeline ✓

---

## PART 2: DAY 2 - SEVERITY SCORING SYSTEM

### 2.1 Scoring Formula

```
final_score = min(100, max(0,
    (base_score + confidence_boost + source_boost + size_bonus)
    * action_multiplier
))
```

### 2.2 Scoring Factors

1. **Base Score by Malware Family** (40-85 points)
   - Ransomware: 85+
   - Trojans/Botnets: 68-75
   - Spyware/Worms: 60-65
   - Unknown: 40

2. **Confidence Boost** (0-20 points)
   - confidence_boost = avg_unified_confidence * 20

3. **Multi-Source Consensus Boost** (0-20 points)
   - +15 per IOC if flagged by ≥3 sources

4. **Group Size Bonus** (0-15 points)
   - 2 IOCs → 4 points
   - 5 IOCs → 10 points
   - 8+ IOCs → 15 points

5. **Action Multiplier**
   - BLOCK: 1.2x
   - MONITOR: 1.0x
   - IGNORE: 0.8x

### 2.3 Severity Levels

| Level     | Score Range | Meaning                              |
|-----------|-------------|--------------------------------------|
| LOW       | 0–30        | Insufficient evidence                |
| MEDIUM    | 31–60       | Suspicious, monitor                  |
| HIGH      | 61–85       | Strong indicators                    |
| CRITICAL  | 86–100      | Immediate action required            |

### 2.4 Testing Results

**12 Unit Tests (All Passing):**
- test_score_high_confidence_group ✓
- test_score_medium_confidence_group ✓
- test_score_low_confidence_group ✓
- test_base_score_calculation ✓
- test_score_to_level ✓
- test_score_to_level_boundaries ✓
- test_action_multiplier ✓
- test_score_multiple_groups ✓
- test_get_high_severity_groups ✓
- test_reasoning_generation ✓
- test_source_boost_calculation ✓
- test_empty_group_handling ✓

---

## STATISTICS & PROGRESS

| Metric        | Day 1 | Day 2 | Total |
|---------------|-------|-------|-------|
| Lines of Code | 250   | 280   | 530   |
| Unit Tests    | 9     | 12    | 21    |
| Pass Rate     | 100%  | 100%  | 100%  |
| Coverage      | 87%   | 89%   | 88%   |

---

## REMAINING TASKS (DAYS 3-7)

- **Day 3:** Main Engine & Union-Find Clustering
- **Day 4:** Optimization & Performance Testing
- **Day 5:** Output Schema & Validation
- **Days 6-7:** Integration Testing & Documentation

---

## SUCCESS CRITERIA

- [x] Rule 1 implemented and tested
- [x] Rule 2 implemented and tested
- [ ] Union-Find clustering working
- [ ] Sample incident output validated
- [ ] >85% code coverage
- [ ] All tests passing (0 failures)
- [ ] Documentation complete

---

## TIMELINE SUMMARY

| Phase | Days | Status |
|-------|------|--------|
| **Core Rules** | 1–2 | ✅ Complete |
| **Scoring** | 3 | 🟡 In Progress |
| **Engine** | 4 | ⏳ To Do |
| **Validation** | 5 | ⏳ To Do |
| **Testing** | 6–7 | ⏳ To Do |

---

**Document Version:** 1.0  
**Status:** Phase 3.1 Implementation In Progress  
**Next Review:** January 8, 2026