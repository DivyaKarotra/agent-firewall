# Ablation Study (FRESH_OLLAMA_V1 Test Set)

Threshold: 0.5

> [!NOTE]
> Percentages include Wilson 95% confidence intervals [lo, hi].
> Differences smaller than the intervals overlap are **not statistically significant**
> at the 95% level. With small N, intervals are wide -- treat narrow wins as noise.

| Configuration | Split | Attacks Caught | False Positive | Avg Latency (ms) | Judge Calls | Judge Time Saved (s) | Judge Errors |
|---|---|---|---|---|---|---|---|
| rules_only | fresh | 35.7% [24.5, 48.8] | 3.4% [0.9, 11.5] | 0.78 | 0 | 421.6s | 0 |
| classifier_only | fresh | 67.9% [54.8, 78.6] | 1.7% [0.3, 9.0] | 27.34 | 0 | 421.6s | 0 |
| judge_only | fresh | 85.7% [74.3, 92.6] | 13.6% [7.0, 24.5] | 4891.43 | 115 | -140.9s | 2 |
| rules_classifier | fresh | 76.8% [64.2, 85.9] | 5.1% [1.7, 13.9] | 23.27 | 0 | 421.6s | 0 |
| full_cascade_max | fresh | 96.4% [87.9, 99.0] | 18.6% [10.7, 30.4] | 3689.23 | 99 | 0.0s | 1 |
| full_cascade_blend | fresh | 94.6% [85.4, 98.2] | 15.3% [8.2, 26.5] | 3689.29 | 99 | 0.0s | 1 |
| full_cascade_verify | fresh | 96.4% [87.9, 99.0] | 18.6% [10.7, 30.4] | 4669.54 | 114 | -112.7s | 2 |
| gated_cascade | fresh | 87.5% [76.4, 93.8] | 6.8% [2.7, 16.2] | 1472.70 | 30 | 255.0s | 1 |

## Attacks Caught by Kind

| Configuration | Kind | Caught/Total | % |
|---|---|---|---|
| rules_only | direct | 4/9 | 44.4% [18.9, 73.3] |
| rules_only | indirect | 4/10 | 40.0% [16.8, 68.7] |
| rules_only | multilingual | 0/12 | 0.0% [0.0, 24.3] |
| rules_only | reworded | 0/8 | 0.0% [0.0, 32.4] |
| rules_only | framed | 1/6 | 16.7% [3.0, 56.4] |
| rules_only | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| rules_only | encoded | 5/5 | 100.0% [56.6, 100.0] |
| classifier_only | direct | 7/9 | 77.8% [45.3, 93.7] |
| classifier_only | indirect | 4/10 | 40.0% [16.8, 68.7] |
| classifier_only | multilingual | 7/12 | 58.3% [32.0, 80.7] |
| classifier_only | reworded | 6/8 | 75.0% [40.9, 92.9] |
| classifier_only | framed | 5/6 | 83.3% [43.6, 97.0] |
| classifier_only | judge_targeted | 5/6 | 83.3% [43.6, 97.0] |
| classifier_only | encoded | 4/5 | 80.0% [37.6, 96.4] |
| judge_only | direct | 9/9 | 100.0% [70.1, 100.0] |
| judge_only | indirect | 9/10 | 90.0% [59.6, 98.2] |
| judge_only | multilingual | 11/12 | 91.7% [64.6, 98.5] |
| judge_only | reworded | 7/8 | 87.5% [52.9, 97.8] |
| judge_only | framed | 6/6 | 100.0% [61.0, 100.0] |
| judge_only | judge_targeted | 2/6 | 33.3% [9.7, 70.0] |
| judge_only | encoded | 4/5 | 80.0% [37.6, 96.4] |
| rules_classifier | direct | 7/9 | 77.8% [45.3, 93.7] |
| rules_classifier | indirect | 7/10 | 70.0% [39.7, 89.2] |
| rules_classifier | multilingual | 7/12 | 58.3% [32.0, 80.7] |
| rules_classifier | reworded | 6/8 | 75.0% [40.9, 92.9] |
| rules_classifier | framed | 5/6 | 83.3% [43.6, 97.0] |
| rules_classifier | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| rules_classifier | encoded | 5/5 | 100.0% [56.6, 100.0] |
| full_cascade_max | direct | 9/9 | 100.0% [70.1, 100.0] |
| full_cascade_max | indirect | 9/10 | 90.0% [59.6, 98.2] |
| full_cascade_max | multilingual | 12/12 | 100.0% [75.7, 100.0] |
| full_cascade_max | reworded | 7/8 | 87.5% [52.9, 97.8] |
| full_cascade_max | framed | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_max | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_max | encoded | 5/5 | 100.0% [56.6, 100.0] |
| full_cascade_blend | direct | 9/9 | 100.0% [70.1, 100.0] |
| full_cascade_blend | indirect | 9/10 | 90.0% [59.6, 98.2] |
| full_cascade_blend | multilingual | 11/12 | 91.7% [64.6, 98.5] |
| full_cascade_blend | reworded | 7/8 | 87.5% [52.9, 97.8] |
| full_cascade_blend | framed | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_blend | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_blend | encoded | 5/5 | 100.0% [56.6, 100.0] |
| full_cascade_verify | direct | 9/9 | 100.0% [70.1, 100.0] |
| full_cascade_verify | indirect | 9/10 | 90.0% [59.6, 98.2] |
| full_cascade_verify | multilingual | 12/12 | 100.0% [75.7, 100.0] |
| full_cascade_verify | reworded | 7/8 | 87.5% [52.9, 97.8] |
| full_cascade_verify | framed | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_verify | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_verify | encoded | 5/5 | 100.0% [56.6, 100.0] |
| gated_cascade | direct | 9/9 | 100.0% [70.1, 100.0] |
| gated_cascade | indirect | 7/10 | 70.0% [39.7, 89.2] |
| gated_cascade | multilingual | 11/12 | 91.7% [64.6, 98.5] |
| gated_cascade | reworded | 6/8 | 75.0% [40.9, 92.9] |
| gated_cascade | framed | 5/6 | 83.3% [43.6, 97.0] |
| gated_cascade | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| gated_cascade | encoded | 5/5 | 100.0% [56.6, 100.0] |

## Action-Aware Outcomes


### rules_only

- **Judge calls**: 0 (99 calls saved vs full_cascade_max, 421.6s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 42 | 0 | 14 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 38 | 4 | 14 |
| normal | 57 | 2 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 38 | 1 | 17 |
| normal | 57 | 2 | 0 |


### classifier_only

- **Judge calls**: 0 (99 calls saved vs full_cascade_max, 421.6s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 51 | 0 | 5 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 42 | 9 | 5 |
| normal | 59 | 0 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 40 | 7 | 9 |
| normal | 59 | 0 | 0 |


### judge_only

- **Judge calls**: 115 (-16 calls saved vs full_cascade_max, -140.9s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 46 | 0 | 10 |
| normal | 51 | 0 | 8 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 10 | 36 | 10 |
| normal | 51 | 0 | 8 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 10 | 36 | 10 |
| normal | 51 | 0 | 8 |


### rules_classifier

- **Judge calls**: 0 (99 calls saved vs full_cascade_max, 421.6s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 40 | 0 | 16 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 32 | 8 | 16 |
| normal | 57 | 2 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 31 | 4 | 21 |
| normal | 57 | 2 | 0 |


### full_cascade_max

- **Judge calls**: 99 (0 calls saved vs full_cascade_max, 0.0s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 32 | 0 | 24 |
| normal | 51 | 0 | 8 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 4 | 28 | 24 |
| normal | 49 | 2 | 8 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 4 | 25 | 27 |
| normal | 49 | 2 | 8 |


### full_cascade_blend

- **Judge calls**: 99 (0 calls saved vs full_cascade_max, 0.0s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 38 | 0 | 18 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 29 | 9 | 18 |
| normal | 59 | 0 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 25 | 12 | 19 |
| normal | 59 | 0 | 0 |


### full_cascade_verify

- **Judge calls**: 114 (-15 calls saved vs full_cascade_max, -112.7s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 35 | 0 | 21 |
| normal | 51 | 0 | 8 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 5 | 30 | 21 |
| normal | 49 | 2 | 8 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 5 | 25 | 26 |
| normal | 49 | 2 | 8 |


### gated_cascade

- **Judge calls**: 30 (69 calls saved vs full_cascade_max, 255.0s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 36 | 0 | 20 |
| normal | 58 | 0 | 1 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 10 | 26 | 20 |
| normal | 56 | 2 | 1 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 9 | 22 | 25 |
| normal | 56 | 2 | 1 |

