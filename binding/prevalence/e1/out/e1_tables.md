## T1 Corpus

- spec files found: 4138; parsed: 4105; failed: 33; parsed only after tab/C1-control-char repair: 2
- distinct API ids (incl. failed files): 2658; APIs with >=1 parsed version: 2652; entries in list.json snapshot: 2529
- version selection: {'preferred (list.json)': 2427, 'not in list.json -> last version dir': 225}
- spec versions (chosen set): {'Swagger 2.0': 984, 'OpenAPI 3.x': 1668}

## T2 Headline (one preferred version per API; strong-tier flags; 95% Wilson CIs)

| subset | APIs | operations | state-changing ops | APIs with >=1 collided key | APIs with >=1 state-changing collided key | ops in collided keys | state-changing ops in collided keys |
|---|---|---|---|---|---|---|---|
| all | 2652 | 127642 | 66184 | 234 (8.8% [7.8, 10.0]) | 225 (10.9% [9.6, 12.3] of 2063 APIs with state ops) | 9420 (7.4% [7.2, 7.5]) | 7577 (11.4% [11.2, 11.7]) |
| excluding amazonaws.com | 2298 | 112078 | 54552 | 66 (2.9% [2.3, 3.6]) | 58 (3.4% [2.6, 4.4] of 1709 APIs with state ops) | 305 (0.3% [0.2, 0.3]) | 197 (0.4% [0.3, 0.4]) |
| excluding amazonaws/azure/googleapis/microsoft | 1329 | 63370 | 29700 | 47 (3.5% [2.7, 4.7]) | 42 (4.5% [3.4, 6.1] of 928 APIs with state ops) | 252 (0.4% [0.4, 0.4]) | 149 (0.5% [0.4, 0.6]) |
| finance (financial|payment) | 106 | 4645 | 2404 | 4 (3.8% [1.5, 9.3]) | 4 (4.9% [1.9, 12.0] of 81 APIs with state ops) | 9 (0.2% [0.1, 0.4]) | 9 (0.4% [0.2, 0.7]) |
| health (keyword) | 15 | 332 | 252 | 2 (13.3% [3.7, 37.9]) | 2 (14.3% [4.0, 39.9] of 14 APIs with state ops) | 39 (11.7% [8.7, 15.7]) | 39 (15.5% [11.5, 20.5]) |

## T3 Per mechanism (chosen set, strong tier)

| mechanism | APIs | collided keys (method,path) | state-changing keys | flagged spec operations | APIs excl. AWS |
|---|---|---|---|---|---|
| M1-query-in-path | 168 | 256 | 202 | 9227 | 8 |
| M2-dispatch-param | 20 | 34 | 21 | 34 | 19 |
| M3-header-dispatch | 0 | 0 | 0 | 0 | 0 |
| M4-body-discriminator | 51 | 156 | 156 | 156 | 43 |
| M5-rpc-endpoint | 3 | 3 | 3 | 3 | 3 |

Sub-types (strong tier):

| mechanism | sub-type | flagged ops | APIs |
|---|---|---|---|
| M1-query-in-path | header(X-Amz-Target, encoded as #fragment) | 5558 | 129 |
| M1-query-in-path | query(encoded as #fragment) | 3549 | 34 |
| M1-query-in-path | query | 75 | 5 |
| M1-query-in-path | base op of a query-variant group (no suffix) | 45 | 12 |
| M2-dispatch-param | query:action | 22 | 13 |
| M2-dispatch-param | query:method | 5 | 3 |
| M2-dispatch-param | query:cmd | 3 | 1 |
| M2-dispatch-param | query:actiontype | 2 | 2 |
| M2-dispatch-param | query:op | 1 | 1 |
| M2-dispatch-param | query:operation | 1 | 1 |
| M4-body-discriminator | prop:action | 87 | 30 |
| M4-body-discriminator | oneOf+discriminator | 16 | 6 |
| M4-body-discriminator | prop:method | 14 | 7 |
| M4-body-discriminator | prop:op | 12 | 1 |
| M4-body-discriminator | prop:operation | 9 | 5 |
| M4-body-discriminator | prop:actiontype | 8 | 4 |
| M4-body-discriminator | anyOf+discriminator | 7 | 1 |
| M4-body-discriminator | prop:action_type | 1 | 1 |
| M4-body-discriminator | prop:command | 1 | 1 |
| M4-body-discriminator | prop:cmd | 1 | 1 |
| M5-rpc-endpoint | jsonrpc-body | 2 | 2 |
| M5-rpc-endpoint | graphql-body | 1 | 1 |

Weak-tier flags (NOT counted above): 672 ops in 89 APIs; by mechanism {'M4-body-discriminator': 567, 'M2-dispatch-param': 103, 'M3-header-dispatch': 2}

## T4 By domain (APIs.guru x-apisguru-categories; an API can carry several; FINANCE/HEALTH are derived)

| category | APIs | APIs w/ collided key | APIs w/ state-changing collided key | state ops | state ops in collided keys | override documented |
|---|---|---|---|---|---|---|
| cloud | 1039 | 176 (16.9% [14.8, 19.3]) | 173 | 16843 | 7407 (44.0% [43.2, 44.7]) | 0 |
| media | 360 | 14 (3.9% [2.3, 6.4]) | 12 | 4667 | 16 (0.3% [0.2, 0.6]) | 0 |
| open_data | 319 | 2 (0.6% [0.2, 2.3]) | 2 | 1223 | 4 (0.3% [0.1, 0.8]) | 0 |
| analytics | 302 | 13 (4.3% [2.5, 7.2]) | 12 | 4037 | 16 (0.4% [0.2, 0.6]) | 0 |
| uncategorized | 187 | 6 (3.2% [1.5, 6.8]) | 6 | 2236 | 11 (0.5% [0.3, 0.9]) | 5 |
| developer_tools | 168 | 8 (4.8% [2.4, 9.1]) | 7 | 27395 | 42 (0.2% [0.1, 0.2]) | 0 |
| FINANCE (financial|payment) | 106 | 4 (3.8% [1.5, 9.3]) | 4 | 2404 | 9 (0.4% [0.2, 0.7]) | 0 |
| ecommerce | 77 | 3 (3.9% [1.3, 10.8]) | 3 | 1579 | 4 (0.3% [0.1, 0.6]) | 0 |
| financial | 73 | 3 (4.1% [1.4, 11.4]) | 3 | 1898 | 7 (0.4% [0.2, 0.8]) | 0 |
| messaging | 64 | 3 (4.7% [1.6, 12.9]) | 2 | 1288 | 5 (0.4% [0.2, 0.9]) | 0 |
| entertainment | 62 | 0 (0.0% [0.0, 5.8]) | 0 | 278 | 0 (0.0% [0.0, 1.4]) | 0 |
| telecom | 61 | 3 (4.9% [1.7, 13.5]) | 3 | 1197 | 18 (1.5% [1.0, 2.4]) | 0 |
| text | 57 | 1 (1.8% [0.3, 9.3]) | 1 | 478 | 5 (1.0% [0.4, 2.4]) | 0 |
| location | 54 | 6 (11.1% [5.2, 22.2]) | 5 | 343 | 5 (1.5% [0.6, 3.4]) | 1 |
| collaboration | 38 | 0 (0.0% [0.0, 9.2]) | 0 | 7708 | 0 (0.0% [0.0, 0.0]) | 0 |
| payment | 35 | 1 (2.9% [0.5, 14.5]) | 1 | 519 | 2 (0.4% [0.1, 1.4]) | 0 |
| transport | 30 | 1 (3.3% [0.6, 16.7]) | 1 | 89 | 1 (1.1% [0.2, 6.1]) | 0 |
| security | 20 | 1 (5.0% [0.9, 23.6]) | 1 | 404 | 9 (2.2% [1.2, 4.2]) | 0 |
| hosting | 20 | 1 (5.0% [0.9, 23.6]) | 1 | 478 | 8 (1.7% [0.9, 3.3]) | 0 |
| social | 19 | 2 (10.5% [2.9, 31.4]) | 2 | 414 | 2 (0.5% [0.1, 1.7]) | 0 |
| iot | 18 | 0 (0.0% [0.0, 17.6]) | 0 | 719 | 0 (0.0% [0.0, 0.5]) | 0 |
| tools | 16 | 0 (0.0% [0.0, 19.4]) | 0 | 1033 | 0 (0.0% [0.0, 0.4]) | 0 |
| HEALTH (title/id keyword) | 15 | 2 (13.3% [3.7, 37.9]) | 2 | 252 | 39 (15.5% [11.5, 20.5]) | 0 |
| enterprise | 14 | 5 (35.7% [16.3, 61.2]) | 4 | 2064 | 31 (1.5% [1.1, 2.1]) | 0 |
| marketing | 13 | 0 (0.0% [0.0, 22.8]) | 0 | 434 | 0 (0.0% [0.0, 0.9]) | 0 |
| email | 13 | 0 (0.0% [0.0, 22.8]) | 0 | 455 | 0 (0.0% [0.0, 0.8]) | 0 |
| machine_learning | 11 | 0 (0.0% [0.0, 25.9]) | 0 | 65 | 0 (0.0% [0.0, 5.6]) | 0 |

(categories with < 10 APIs omitted from this table; all are in e1_by_category.csv)

## T5 Method override documented in the spec: 6 of 2652 APIs (0.2% [0.1, 0.5])

| API | evidence |
|---|---|
| amadeus.com | POST /shopping/flight-offers param header:X-HTTP-Method-Override |
| amadeus.com:amadeus-branded-fares-upsell | POST /shopping/flight-offers/upselling param header:X-HTTP-Method-Override |
| amadeus.com:amadeus-flight-availabilities-search | POST /shopping/availability/flight-availabilities param header:X-HTTP-Method-Override |
| amadeus.com:amadeus-flight-choice-prediction | POST /shopping/flight-offers/prediction param header:X-HTTP-Method-Override |
| amadeus.com:amadeus-flight-offers-price | POST /shopping/flight-offers/pricing param header:X-HTTP-Method-Override |
| amadeus.com:amadeus-seatmap-display | POST /shopping/seatmaps param header:X-HTTP-Method-Override |

## T6 GraphQL / JSON-RPC single endpoints (strong tier): 3 APIs

| API | method | path | signal |
|---|---|---|---|
| mastercard.com:MAWS | POST | `/v1/maws` | jsonrpc-body |
| nebl.io | POST | `/` | jsonrpc-body |
| redhat.com:catalog_inventory | POST | `/graphql` | graphql-body |

## T7 Largest non-AWS APIs by state-changing operations inside collided keys

| API | categories | state ops | state ops in collided keys | mechanisms |
|---|---|---|---|---|
| box.com | cloud | 144 | 21 | M1-query-in-path|M4-body-discriminator |
| mist.com | enterprise | 406 | 20 | M4-body-discriminator |
| microsoft.com:graph-beta | developer_tools | 11230 | 18 | M4-body-discriminator |
| microsoft.com:graph | developer_tools | 5598 | 14 | M4-body-discriminator |
| zoom.us | telecom | 200 | 12 | M2-dispatch-param|M4-body-discriminator |
| ix-api.net | security | 35 | 9 | M4-body-discriminator |
| digitalocean.com | hosting | 145 | 8 | M4-body-discriminator |
| loket.nl | enterprise | 309 | 7 | M4-body-discriminator |
| opensuse.org:obs | developer_tools | 33 | 6 | M1-query-in-path|M2-dispatch-param |
| formapi.io | text | 21 | 5 | M1-query-in-path |
| twilio.com:api | telecom|messaging | 92 | 4 | M4-body-discriminator |
| bbc.co.uk | media | 31 | 3 | M2-dispatch-param|M4-body-discriminator |
| i-cue.solutions | analytics | 52 | 3 | M4-body-discriminator |
| illumidesk.com | open_data | 86 | 3 | M4-body-discriminator |
| mastercard.com:masterpassqr | uncategorized | 12 | 3 | M1-query-in-path |
| nexmo.com:conversation | uncategorized | 13 | 3 | M4-body-discriminator |
| probely.com | monitoring | 75 | 3 | M4-body-discriminator |
| visma.net | enterprise | 240 | 3 | M4-body-discriminator |
| zuora.com | financial | 256 | 3 | M4-body-discriminator |
| ably.net:control | cloud | 15 | 2 | M4-body-discriminator |
| exavault.com | storage | 35 | 2 | M2-dispatch-param|M4-body-discriminator |
| googleapis.com:appengine | analytics|media | 20 | 2 | M4-body-discriminator |
| googleapis.com:container | analytics|media | 45 | 2 | M4-body-discriminator |
| gsmtasks.com | uncategorized | 144 | 2 | M2-dispatch-param|M4-body-discriminator |
| rebilly.com | payment|ecommerce | 107 | 2 | M4-body-discriminator |

## T8 Sensitivity: all parsed spec files (every version counted)

| subset | spec files | operations | state-changing ops | files with >=1 collided key | files with >=1 state-changing collided key | ops in collided keys | state-changing ops in collided keys |
|---|---|---|---|---|---|---|---|
| all files | 4105 | 156729 | 81710 | 261 (6.4% [5.7, 7.1]) | 249 (7.6% [6.7, 8.5] of 3282 APIs with state ops) | 9948 (6.3% [6.2, 6.5]) | 7871 (9.6% [9.4, 9.8]) |
| all files excl. AWS | 3736 | 140362 | 69632 | 81 (2.2% [1.7, 2.7]) | 70 (2.4% [1.9, 3.0] of 2913 APIs with state ops) | 324 (0.2% [0.2, 0.3]) | 212 (0.3% [0.3, 0.3]) |
