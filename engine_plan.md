# 🚀 CORRELATION ENGINE WITH UNION-FIND & CLI DEMO
## Phase 3.1 - Week 6 Implementation

**Status:** Ready to implement ✅  
**Files to create:** 2  
**Total LOC:** ~350  
**Time:** 2-3 hours  

---

## 📋 IMPLEMENTATION PLAN

### File 1: `src/correlation/engine.py` (180-200 LOC)
- Union-Find clustering algorithm
- Main orchestrator combining Rules + Scorer
- Incident group generation
- Deduplication logic

### File 2: `demo_cli.py` (120-150 LOC)
- Command-line interface
- End-to-end demo
- Test data generation
- Output formatting

---

## 🎯 WHAT GETS BUILT

```
INPUT (Enriched IOCs)
    ↓
[Rule 1: Infrastructure Correlation]
    ↓
[Rule 2: Malware Family Correlation]
    ↓
[Union-Find Clustering - Deduplication]
    ↓
[Severity Scoring - 5 factors]
    ↓
OUTPUT (Incident Groups with Scores)
```

---

## 💡 KEY ALGORITHMS

### Union-Find (Disjoint Set Union)
```
Purpose: Efficiently cluster IOCs
Time Complexity: O(α(n)) ≈ O(1) amortized
Space Complexity: O(n)

Operations:
- find(x): Get root parent of element
- union(x, y): Merge two sets
- Connected(x, y): Check if connected
```

### Deduplication
```
Problem: Same IOC appears in multiple rules
Solution: Track seen IOCs, prevent duplicates
Result: Clean incident groups
```

### Scoring (5 factors)
```
1. Malware family base score
2. Confidence boost (avg unified confidence)
3. Source consensus (multi-source)
4. Size bonus (more IOCs = higher score)
5. Action multiplier (BLOCK vs IGNORE)
```

---

## 📁 FILE STRUCTURE

After implementation:

```
src/correlation/
├── __init__.py
├── rules.py          ✅ (exists, 155 LOC)
├── scorer.py         ✅ (exists, 244 LOC)
└── engine.py         ← CREATE THIS (180-200 LOC)

demo_cli.py          ← CREATE THIS (120-150 LOC)
```

---

## 🔧 STEP-BY-STEP CREATION

### Step 1: Create `src/correlation/engine.py`

**Location:** `src/correlation/engine.py`

**Contains:**
- UnionFind class
- CorrelationEngine class
- Deduplication logic
- Orchestration

### Step 2: Create `demo_cli.py`

**Location:** `demo_cli.py` (project root)

**Contains:**
- CLI argument parsing
- Sample data generation
- End-to-end demo
- Results display

---

## ✅ AFTER IMPLEMENTATION

You'll have:

✅ Production-ready correlation engine  
✅ Working Union-Find clustering  
✅ Deduplication working  
✅ Severity scoring integrated  
✅ CLI demo script  
✅ All 21 tests passing  
✅ Ready for Phase 3.1 submission  

---

## 🎯 READY TO CODE?

See the actual implementation code in the next section!

This guide outlines the structure and flow.
The actual .py files will have complete working code.

---

## 📊 COMPLETION CHECKLIST

- [ ] Create engine.py
- [ ] Create demo_cli.py
- [ ] Run pytest: All tests pass
- [ ] Run demo: Works end-to-end
- [ ] Commit to git
- [ ] Push to GitHub

---

## 🚀 WHAT'S NEXT

**Today (Fri):** Create these files + test  
**Tomorrow (Sat):** Debug if needed  
**Monday (Mon):** Final polish + submit  

---

**Ready to build? Let me create the actual code files! 💪**
