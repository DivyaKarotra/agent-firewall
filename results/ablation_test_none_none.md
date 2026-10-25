# Ablation Study (TEST_NONE_NONE Test Set)

Threshold: 0.5

> [!NOTE]
> Percentages include Wilson 95% confidence intervals [lo, hi].
> Differences smaller than the intervals overlap are **not statistically significant**
> at the 95% level. With small N, intervals are wide -- treat narrow wins as noise.

| Configuration | Split | Attacks Caught | False Positive | Avg Latency (ms) | Judge Calls | Judge Time Saved (s) | Judge Errors |
|---|---|---|---|---|---|---|---|
| rules_only | test | 82.9% [67.3, 91.9] | 10.0% [3.5, 25.6] | 0.88 | 0 | 0.0s | 0 |
| classifier_only | test | 94.3% [81.4, 98.4] | 6.7% [1.8, 21.3] | 26.66 | 0 | 0.0s | 0 |
| rules_classifier | test | 100.0% [90.1, 100.0] | 13.3% [5.3, 29.7] | 18.05 | 0 | 0.0s | 0 |

## Attacks Caught by Kind

| Configuration | Kind | Caught/Total | % |
|---|---|---|---|
| rules_only | direct | 8/9 | 88.9% [56.5, 98.0] |
| rules_only | indirect | 9/9 | 100.0% [70.1, 100.0] |
| rules_only | multilingual | 1/4 | 25.0% [4.6, 69.9] |
| rules_only | reworded | 2/4 | 50.0% [15.0, 85.0] |
| rules_only | judge_targeted | 4/4 | 100.0% [51.0, 100.0] |
| rules_only | encoded | 5/5 | 100.0% [56.6, 100.0] |
| classifier_only | direct | 29/29 | 100.0% [88.3, 100.0] |
| classifier_only | indirect | 29/29 | 100.0% [88.3, 100.0] |
| classifier_only | multilingual | 12/12 | 100.0% [75.7, 100.0] |
| classifier_only | reworded | 13/13 | 100.0% [77.2, 100.0] |
| classifier_only | framed | 12/12 | 100.0% [75.7, 100.0] |
| classifier_only | judge_targeted | 14/14 | 100.0% [78.5, 100.0] |
| classifier_only | encoded | 11/13 | 84.6% [57.8, 95.7] |
| rules_classifier | direct | 9/9 | 100.0% [70.1, 100.0] |
| rules_classifier | indirect | 9/9 | 100.0% [70.1, 100.0] |
| rules_classifier | multilingual | 4/4 | 100.0% [51.0, 100.0] |
| rules_classifier | reworded | 4/4 | 100.0% [51.0, 100.0] |
| rules_classifier | judge_targeted | 4/4 | 100.0% [51.0, 100.0] |
| rules_classifier | encoded | 5/5 | 100.0% [56.6, 100.0] |

## Action-Aware Outcomes


### rules_only

- **Judge calls**: 0

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 13 | 0 | 22 |
| normal | 30 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 9 | 4 | 22 |
| normal | 28 | 2 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 9 | 2 | 24 |
| normal | 28 | 1 | 1 |


### classifier_only

- **Judge calls**: 0

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 43 | 0 | 79 |
| normal | 131 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 13 | 30 | 79 |
| normal | 131 | 0 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 6 | 23 | 93 |
| normal | 131 | 0 | 0 |


### rules_classifier

- **Judge calls**: 0

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 9 | 0 | 26 |
| normal | 30 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 4 | 5 | 26 |
| normal | 28 | 2 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 3 | 4 | 28 |
| normal | 28 | 1 | 1 |

