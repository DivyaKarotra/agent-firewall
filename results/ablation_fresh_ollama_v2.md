# Ablation Study (FRESH_OLLAMA_V2 Test Set)

Threshold: 0.5

> [!NOTE]
> Percentages include Wilson 95% confidence intervals [lo, hi].
> Differences smaller than the intervals overlap are **not statistically significant**
> at the 95% level. With small N, intervals are wide -- treat narrow wins as noise.

| Configuration | Split | Attacks Caught | False Positive | Avg Latency (ms) | Judge Calls | Judge Time Saved (s) | Judge Errors |
|---|---|---|---|---|---|---|---|
| rules_only | fresh | 35.7% [24.5, 48.8] | 3.4% [0.9, 11.5] | 1.23 | 0 | 322.7s | 0 |
| classifier_only | fresh | 76.8% [64.2, 85.9] | 1.7% [0.3, 9.0] | 25.60 | 0 | 322.7s | 0 |
| judge_only | fresh | 76.8% [64.2, 85.9] | 6.8% [2.7, 16.2] | 3363.71 | 115 | -64.1s | 0 |
| rules_classifier | fresh | 83.9% [72.2, 91.3] | 5.1% [1.7, 13.9] | 23.54 | 0 | 322.7s | 0 |
| full_cascade_max | fresh | 92.9% [83.0, 97.2] | 11.9% [5.9, 22.5] | 2829.29 | 96 | 0.0s | 0 |
| full_cascade_blend | fresh | 85.7% [74.3, 92.6] | 8.5% [3.7, 18.4] | 2829.74 | 96 | 0.0s | 0 |
| full_cascade_verify | fresh | 85.7% [74.3, 92.6] | 8.5% [3.7, 18.4] | 3270.53 | 111 | -50.6s | 0 |
| gated_cascade | fresh | 85.7% [74.3, 92.6] | 5.1% [1.7, 13.9] | 802.60 | 27 | 233.0s | 0 |

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
| classifier_only | direct | 9/9 | 100.0% [70.1, 100.0] |
| classifier_only | indirect | 4/10 | 40.0% [16.8, 68.7] |
| classifier_only | multilingual | 9/12 | 75.0% [46.8, 91.1] |
| classifier_only | reworded | 6/8 | 75.0% [40.9, 92.9] |
| classifier_only | framed | 5/6 | 83.3% [43.6, 97.0] |
| classifier_only | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| classifier_only | encoded | 4/5 | 80.0% [37.6, 96.4] |
| judge_only | direct | 9/9 | 100.0% [70.1, 100.0] |
| judge_only | indirect | 10/10 | 100.0% [72.2, 100.0] |
| judge_only | multilingual | 4/12 | 33.3% [13.8, 60.9] |
| judge_only | reworded | 8/8 | 100.0% [67.6, 100.0] |
| judge_only | framed | 5/6 | 83.3% [43.6, 97.0] |
| judge_only | judge_targeted | 4/6 | 66.7% [30.0, 90.3] |
| judge_only | encoded | 3/5 | 60.0% [23.1, 88.2] |
| rules_classifier | direct | 9/9 | 100.0% [70.1, 100.0] |
| rules_classifier | indirect | 7/10 | 70.0% [39.7, 89.2] |
| rules_classifier | multilingual | 9/12 | 75.0% [46.8, 91.1] |
| rules_classifier | reworded | 6/8 | 75.0% [40.9, 92.9] |
| rules_classifier | framed | 5/6 | 83.3% [43.6, 97.0] |
| rules_classifier | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| rules_classifier | encoded | 5/5 | 100.0% [56.6, 100.0] |
| full_cascade_max | direct | 9/9 | 100.0% [70.1, 100.0] |
| full_cascade_max | indirect | 10/10 | 100.0% [72.2, 100.0] |
| full_cascade_max | multilingual | 9/12 | 75.0% [46.8, 91.1] |
| full_cascade_max | reworded | 8/8 | 100.0% [67.6, 100.0] |
| full_cascade_max | framed | 5/6 | 83.3% [43.6, 97.0] |
| full_cascade_max | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_max | encoded | 5/5 | 100.0% [56.6, 100.0] |
| full_cascade_blend | direct | 9/9 | 100.0% [70.1, 100.0] |
| full_cascade_blend | indirect | 10/10 | 100.0% [72.2, 100.0] |
| full_cascade_blend | multilingual | 6/12 | 50.0% [25.4, 74.6] |
| full_cascade_blend | reworded | 8/8 | 100.0% [67.6, 100.0] |
| full_cascade_blend | framed | 5/6 | 83.3% [43.6, 97.0] |
| full_cascade_blend | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| full_cascade_blend | encoded | 4/5 | 80.0% [37.6, 96.4] |
| full_cascade_verify | direct | 9/9 | 100.0% [70.1, 100.0] |
| full_cascade_verify | indirect | 10/10 | 100.0% [72.2, 100.0] |
| full_cascade_verify | multilingual | 9/12 | 75.0% [46.8, 91.1] |
| full_cascade_verify | reworded | 8/8 | 100.0% [67.6, 100.0] |
| full_cascade_verify | framed | 5/6 | 83.3% [43.6, 97.0] |
| full_cascade_verify | judge_targeted | 4/6 | 66.7% [30.0, 90.3] |
| full_cascade_verify | encoded | 3/5 | 60.0% [23.1, 88.2] |
| gated_cascade | direct | 9/9 | 100.0% [70.1, 100.0] |
| gated_cascade | indirect | 8/10 | 80.0% [49.0, 94.3] |
| gated_cascade | multilingual | 9/12 | 75.0% [46.8, 91.1] |
| gated_cascade | reworded | 6/8 | 75.0% [40.9, 92.9] |
| gated_cascade | framed | 5/6 | 83.3% [43.6, 97.0] |
| gated_cascade | judge_targeted | 6/6 | 100.0% [61.0, 100.0] |
| gated_cascade | encoded | 5/5 | 100.0% [56.6, 100.0] |

## Action-Aware Outcomes


### rules_only

- **Judge calls**: 0 (96 calls saved vs full_cascade_max, 322.7s judge time saved)

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

- **Judge calls**: 0 (96 calls saved vs full_cascade_max, 322.7s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 46 | 0 | 10 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 38 | 8 | 10 |
| normal | 59 | 0 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 32 | 8 | 16 |
| normal | 59 | 0 | 0 |


### judge_only

- **Judge calls**: 115 (-19 calls saved vs full_cascade_max, -64.1s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 40 | 0 | 16 |
| normal | 55 | 0 | 4 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 13 | 27 | 16 |
| normal | 55 | 0 | 4 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 13 | 27 | 16 |
| normal | 55 | 0 | 4 |


### rules_classifier

- **Judge calls**: 0 (96 calls saved vs full_cascade_max, 322.7s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 37 | 0 | 19 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 29 | 8 | 19 |
| normal | 57 | 2 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 26 | 4 | 26 |
| normal | 57 | 2 | 0 |


### full_cascade_max

- **Judge calls**: 96 (0 calls saved vs full_cascade_max, 0.0s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 23 | 0 | 33 |
| normal | 55 | 0 | 4 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 7 | 16 | 33 |
| normal | 53 | 2 | 4 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 6 | 13 | 37 |
| normal | 53 | 2 | 4 |


### full_cascade_blend

- **Judge calls**: 96 (0 calls saved vs full_cascade_max, 0.0s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 33 | 0 | 23 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 26 | 7 | 23 |
| normal | 59 | 0 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 21 | 8 | 27 |
| normal | 59 | 0 | 0 |


### full_cascade_verify

- **Judge calls**: 111 (-15 calls saved vs full_cascade_max, -50.6s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 28 | 0 | 28 |
| normal | 55 | 0 | 4 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 11 | 17 | 28 |
| normal | 55 | 0 | 4 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 10 | 14 | 32 |
| normal | 55 | 0 | 4 |


### gated_cascade

- **Judge calls**: 27 (69 calls saved vs full_cascade_max, 233.0s judge time saved)

#### Low Risk Tools (ASK=None, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 31 | 0 | 25 |
| normal | 59 | 0 | 0 |

#### Medium Risk Tools (ASK=0.80, BLOCK=0.90)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 13 | 18 | 25 |
| normal | 57 | 2 | 0 |

#### High Risk Tools (ASK=0.75, BLOCK=0.85)

| | ALLOW | ASK | BLOCK |
|---|---|---|---|
| attacks | 10 | 14 | 32 |
| normal | 57 | 2 | 0 |

