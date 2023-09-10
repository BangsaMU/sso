<?php
return [
    'curl' => array(
        'TIMEOUT' => 30,
        'VERIFY' => false,
        'LIST_NETWORK' => env('APP_LIST_NETWORK'),
    ),
    'main' => array(
        'APP_CODE' => 'APP03', /*32 digit  char random untuk hasing token harus sama antara server an client untuk decode token dari server */
        'KEY' => 'Jp1cwQuACtrWwnN9sORA1P4TIOpSqH4VEg05FLf7DHI=', /*32 digit  char random untuk hasing token harus sama antara server an client untuk decode token dari server */
        // 'KEY' => 'YUcyZEM1UWRoY2c3UFhYemMyMktvekJhQ1Baa0x5R2U=', /*32 digit  char random untuk hasing token harus sama antara server an client*/
        'ACTIVE' => env('SSO_ACTIVE', false), /*jika akan login mengunakan sso set ke true [true,false]*/
        'TOKEN' => 'eyJpdiI6IkdQUXprMi9CSnFkMVBWNHJjb3dTVGc9PSIsInZhbHVlIjoiR0s4bUd1bDdjd2JGbVlOZm5URERLUT09IiwibWFjIjoiOGQzZmNkMTA2NjcxZGYxMDhkNzY3ZjE1ZTg1YWUyMTQ3OWExZGFhMWVmMTQxNTlmZTU0MjA3ZjE0NGU2MzVlNiIsInRhZyI6IiJ9', /*auth untuk masuk ke sytem api sso*/
        'URL' => env('SSO_URL', 'http://sso.test'), /*harus diakhiri dengan / (slash) */
        'CALL_BACK' => '',
    ),
];
