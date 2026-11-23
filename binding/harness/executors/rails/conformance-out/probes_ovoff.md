### Probes: rails OVERRIDE=off

| id | request | status | op_id | effective method | path_params |
|---|---|---|---|---|---|
| canon | `GET /api/v1/accounts/acc-alice-1` | 200 | getAccount | GET | {"id": "acc-alice-1"} |
| enc-slash | `GET /api/v1/accounts/acc%2Falice` | 200 | getAccount | GET | {"id": "acc/alice"} |
| enc-slash-lc | `GET /api/v1/accounts/acc%2falice` | 200 | getAccount | GET | {"id": "acc/alice"} |
| enc-unreserved | `GET /api/v1/%61ccounts/acc-alice-1` | 404 | NOT_FOUND | GET |  |
| enc-id | `GET /api/v1/accounts/acc%2Dalice-1` | 200 | getAccount | GET | {"id": "acc-alice-1"} |
| dot-seg | `GET /api/v1/admin/../accounts/acc-alice-1` | 404 | NOT_FOUND | GET |  |
| dot-seg-enc | `GET /api/v1/admin/%2e%2e/accounts/acc-alice-1` | 404 | NOT_FOUND | GET |  |
| dot-single | `GET /api/v1/./accounts/acc-alice-1` | 404 | NOT_FOUND | GET |  |
| matrix-lit | `GET /api/v1/accounts;x=1/acc-alice-1` | 404 | NOT_FOUND | GET |  |
| matrix-var | `GET /api/v1/accounts/acc-alice-1;x=1` | 200 | getAccount | GET | {"id": "acc-alice-1;x=1"} |
| matrix-admin | `DELETE /api/v1/admin;x=1/users/u-1` | 404 | NOT_FOUND | DELETE |  |
| trail-coll | `GET /api/v1/accounts/` | 200 | listAccounts | GET |  |
| trail-item | `GET /api/v1/accounts/acc-alice-1/` | 200 | getAccount | GET | {"id": "acc-alice-1"} |
| dbl-mid | `GET /api/v1//accounts/acc-alice-1` | 200 | getAccount | GET | {"id": "acc-alice-1"} |
| dbl-lead | `GET //api/v1/accounts` | 200 | listAccounts | GET |  |
| case-lit | `GET /api/v1/ACCOUNTS` | 404 | NOT_FOUND | GET |  |
| case-prefix | `GET /API/v1/accounts` | 404 | NOT_FOUND | GET |  |
| suffix | `GET /api/v1/accounts/acc-alice-1.json` | 200 | getAccount | GET | {"id": "acc-alice-1"} |
| suffix-coll | `GET /api/v1/accounts.json` | 200 | listAccounts | GET |  |
| backslash | `GET /api/v1\accounts` | 400 |  |  |  |
| enc-backslash | `GET /api/v1%5Caccounts` | 404 | NOT_FOUND | GET |  |
| enc-qmark | `GET /api/v1/accounts/acc%3Fx` | 200 | getAccount | GET | {"id": "acc?x"} |
| nul | `GET /api/v1/accounts/acc%00x` | 200 | getAccount | GET | {"id": "acc\u0000x"} |
| fragment | `GET /api/v1/me#frag` | 200 | me | GET |  |
| abs-form | `GET http://api.bench.test/api/v1/me` | 200 | me | GET |  |
| v2-prefix | `GET /api/v2/accounts/acc-alice-1` | 200 | getAccountV2 | GET | {"id": "acc-alice-1"} |
| v2-dotdot | `GET /api/v2/../v1/admin/users` | 404 | NOT_FOUND | GET |  |
| v2-dbl | `GET /api/v2//accounts/acc-alice-1` | 200 | getAccountV2 | GET | {"id": "acc-alice-1"} |
| v2-case | `GET /api/V2/accounts/acc-alice-1` | 404 | NOT_FOUND | GET |  |
| method-lc | `get /api/v1/accounts/acc-alice-1` | 400 |  |  |  |
| head | `HEAD /api/v1/accounts/acc-alice-1` | 200 |  |  |  |
| options | `OPTIONS /api/v1/accounts/acc-alice-1` | 404 | NOT_FOUND | OPTIONS |  |
| op-dup-fc | `POST /api/v1/accounts/acc-alice-1/actions?op=freeze&op=close` body `{}` | 200 | accountAction.close | POST | {"id": "acc-alice-1"} |
| op-dup-cf | `POST /api/v1/accounts/acc-alice-1/actions?op=close&op=freeze` body `{}` | 200 | accountAction.freeze | POST | {"id": "acc-alice-1"} |
| op-arr | `POST /api/v1/accounts/acc-alice-1/actions?op[]=close` body `{}` | 200 | accountAction.unknown | POST | {"id": "acc-alice-1"} |
| op-enc | `POST /api/v1/accounts/acc-alice-1/actions?%6Fp=close` body `{}` | 200 | accountAction.close | POST | {"id": "acc-alice-1"} |
| op-form | `POST /api/v1/accounts/acc-alice-1/actions` body `op=close` | 200 | accountAction.close | POST | {"id": "acc-alice-1"} |
| op-form-vs-q | `POST /api/v1/accounts/acc-alice-1/actions?op=freeze` body `op=close` | 200 | accountAction.freeze | POST | {"id": "acc-alice-1"} |
| op-json | `POST /api/v1/accounts/acc-alice-1/actions` body `{"op":"close"}` | 200 | accountAction.close | POST | {"id": "acc-alice-1"} |
| op-semicolon | `POST /api/v1/accounts/acc-alice-1/actions?x=1;op=close` body `{}` | 200 | accountAction.unknown | POST | {"id": "acc-alice-1"} |
| gql-dupkey | `POST /api/v1/graphql` body `{"operationName":"getProfile","operationName":"deleteProfile"}` | 200 | graphql.unknown | POST |  |
| gql-text | `POST /api/v1/graphql` body `{"operationName":"deleteProfile"}` | 200 | graphql.deleteProfile | POST |  |
| ov-hdr | `POST /api/v1/accounts/acc-alice-1` {'X-HTTP-Method-Override': 'DELETE'} body `{}` | 404 | NOT_FOUND | POST |  |
| ov-hdr-put | `POST /api/v1/accounts/acc-alice-1` {'X-HTTP-Method-Override': 'PUT'} body `{}` | 404 | NOT_FOUND | POST |  |
| ov-hdr-get | `POST /api/v1/accounts/acc-alice-1` {'X-HTTP-Method-Override': 'GET'} body `{}` | 404 | NOT_FOUND | POST |  |
| ov-hdr-lc | `POST /api/v1/accounts/acc-alice-1` {'X-HTTP-Method-Override': 'delete'} body `{}` | 404 | NOT_FOUND | POST |  |
| ov-hdr-onget | `GET /api/v1/accounts/acc-alice-1` {'X-HTTP-Method-Override': 'DELETE'} | 200 | getAccount | GET | {"id": "acc-alice-1"} |
| ov-hdr-onput | `PUT /api/v1/accounts/acc-alice-1` {'X-HTTP-Method-Override': 'DELETE'} body `{}` | 200 | updateAccount | PUT | {"id": "acc-alice-1"} |
| ov-xhm | `POST /api/v1/accounts/acc-alice-1` {'X-HTTP-Method': 'DELETE'} body `{}` | 404 | NOT_FOUND | POST |  |
| ov-xmo | `POST /api/v1/accounts/acc-alice-1` {'X-Method-Override': 'DELETE'} body `{}` | 404 | NOT_FOUND | POST |  |
| ov-q | `POST /api/v1/accounts/acc-alice-1?_method=DELETE` body `{}` | 404 | NOT_FOUND | POST |  |
| ov-form | `POST /api/v1/accounts/acc-alice-1` body `_method=DELETE` | 404 | NOT_FOUND | POST |  |
| ov-form-lc | `POST /api/v1/accounts/acc-alice-1` body `_method=delete` | 404 | NOT_FOUND | POST |  |
| ov-form-get | `POST /api/v1/accounts/acc-alice-1` body `_method=GET` | 404 | NOT_FOUND | POST |  |
| ov-json | `POST /api/v1/accounts/acc-alice-1` body `{"_method":"DELETE"}` | 404 | NOT_FOUND | POST |  |
| ov-form-admin | `POST /api/v1/admin/users/u-1` body `_method=DELETE` | 404 | NOT_FOUND | POST |  |
| ov-hdr-admin | `POST /api/v1/admin/users/u-1` {'X-HTTP-Method-Override': 'DELETE'} body `{}` | 404 | NOT_FOUND | POST |  |
| ov-both | `POST /api/v1/accounts/acc-alice-1` {'X-HTTP-Method-Override': 'DELETE'} body `_method=PUT` | 404 | NOT_FOUND | POST |  |
