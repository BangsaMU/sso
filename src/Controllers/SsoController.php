<?php

namespace Bangsamu\Sso\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

use Carbon\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Validator;
use Response;
use Illuminate\Support\Str;
use App\Models\Telegram;

use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;


use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\FacadesAuth;
use App\Models\Session;

use Illuminate\Encryption\Encrypter;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

use Illuminate\Support\Facades\Auth;

class SsoController extends Controller
{
    public $CHAT_ID;
    public $param;

    function __construct($CHAT_ID = null, $param = null)
    {
        $this->CHAT_ID = $CHAT_ID ?? config('SsoConfig.main.CHAT_ID', '-1001983435070');
        $this->param = $param;
    }

    /**
     * Fungsi untuk setup ke url api telgram
     *
     * @param action string berisi parammeter fungsi api dari telegram
     * @param token string berisi token untuk akses auth, jika kosong akan di ambil dari TOKEN di config
     *
     * @return string berisi return full url untuk akses ke api telegram
     */
    function loginSso($action, $param = null, $token = null)
    {
        $param_segment = isset($param) ? $param . '/' : '';
        $api_token = $token ?? config('SsoConfig.main.TOKEN');
        $uRL = config('SsoConfig.main.URL', url('/')) . $param_segment . $action;
        // $uRL = config('SsoConfig.main.URL', url('/')) . $param_segment . $api_token . '/' . $action;
        return $uRL;
    }


    /**
     * Fungsi awal sebelum melakukan request ke api telgram, mengunakan bawan http call dungsi curl dari laravel
     *
     * @return mix berisi object untuk request http laravel
     */
    public function init()
    {
        $ssoSend = Http::timeout(config('SsoConfig.curl.TIMEOUT', 30))->withOptions([
            'verify' => config('SsoConfig.curl.VERIFY', false),
        ]);
        return $ssoSend;
    }

    /**
     * Fungsi untuk kirim validasi format error
     *
     * @param error array berisi list data yang error
     *
     * @return json berisi return dari format function setOutput
     */
    function validateError($error = null)
    {
        $data['status'] =  'gagal';
        $data['code'] = '400';
        $data['data'] = $error;

        return self::setOutput($data);
    }

    /**
     * Fungsi untuk standart return output respond
     *
     * @param respond mix data bisa json maupun object
     * @param type jenis dari respond yang di harapkan [json,body,object]
     *
     * @return mix respond data dari param type defaultnya json
     */
    function setOutput($respon = null, $type = 'json')
    {
        // dd(9,$type,$respon);
        if ($type == 'json') {
            // $return = $respon->{$type}();

            $status = @$respon['status'] ?? 'sukses';
            $code = @$respon['code'] ?? '200';
            $data = @$respon['data'] ?? $respon->object();
            $return['status'] = $status;
            $return['code'] = $code;
            $return['data'] = $data;
            // dd($return);
        } else {
            $return = $respon->{$type}();
        }
        return $return;
    }

    /**
     * Fungsi untuk validasi param request
     * jika tidak ada param document maka akan upload activity kemarin
     *
     * @param  \Illuminate\Http\Request  $request
     * @param rules array berisi list data rule yang di harapkan
     *
     * @return mix akan return boolean true jika sukses jika gagal akan respod json untuk data errornya
     */
    public function validator($request_all, $rules)
    {
        $validator = Validator::make($request_all, $rules);
        if ($validator->fails()) {
            $error = $validator->errors();
            $return['status'] = 'gagal';
            $return['code'] = 204;
            $return['data'] = $error->getMessages();
            return  self::setOutput($return);
            // Response::make(self::validateError($error))->send();
            // exit();
        }
        return true;
    }

    /**
     * Fungsi untuk validasi telgram respond
     * jika gagal makan akan dikirim detail respond erro dari telegram
     *
     * @param ssoSend retun data object dari http cal ke api telegram
     *
     * @return json respond data dengan format standart json
     */
    public function ssoRespond($ssoSend)
    {
        // dd($ssoSend->object());
        if ($ssoSend->failed()) {
            $respond['status'] = 'gagal';
            $respond['code'] = '204';
            $respond['data'] = $ssoSend->object();

            $data = $respond;
        } else {
            $data = $ssoSend;
            // self::saveDB($data);
        }

        // Log::info('user: sys url: ' . url()->current() . ' message: done backup to TELEGRAM log respond :' . json_encode($data));

        return self::setOutput($data);
    }

    public function saveDB($data)
    {

        if (isset($data->ok)) {
            $result = $data->result;

            if (isset($result->message_id)) {
                $created['message_id'] = @$result->message_id;
            }
            if (isset($result->from)) {
                $created['from_id'] = @$result->from->id;
                $created['from_is_bot'] = @$result->from->is_bot;
                $created['from_first_name'] = @$result->from->first_name;
                $created['from_username'] = @$result->from->username;
            }
            if (isset($result->chat)) {
                $created['chat_id'] = @$result->chat->id;
                $created['chat_first_name'] = @$result->chat->first_name;
                $created['chat_username'] = @$result->chat->username;
                $created['chat_type'] = @$result->chat->type;
            }
            if (isset($result->date)) {
                $created['date'] = @$result->date;
            }
            if (isset($result->caption)) {
                $created['caption'] = @$result->caption;
            }
            if (isset($result->text)) {
                $created['text'] = @$result->text;
            }
            if (isset($result->document)) {
                $created['document'] = json_encode(@$result->document);
            }
            if (isset($result->entities)) {
                $created['entities'] = json_encode(@$result->entities);
            }
            if (isset($result->photo)) {
                $created['photo'] = json_encode(@$result->photo);
            }
            $created['raw'] = json_encode($data);
            $telegram_db = Telegram::create($created);
        } else {
            $telegram_db = false;
        };
        // dd($telegram_db, isset($data->ok), $data);
        return $telegram_db;
    }

    public function getIp()
    {
        // foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key) {
        //     if (array_key_exists($key, $_SERVER) === true) {
        //         foreach (explode(',', $_SERVER[$key]) as $ip) {
        //             $ip = trim($ip); // just to be safe
        //             if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
        //                 return $ip;
        //             }
        //         }
        //     }
        // }

        if (isset($_SERVER['HTTP_CLIENT_IP']))
            $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
        else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
            $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
        else if (isset($_SERVER['HTTP_X_FORWARDED']))
            $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
        else if (isset($_SERVER['HTTP_FORWARDED_FOR']))
            $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
        else if (isset($_SERVER['HTTP_FORWARDED']))
            $ipaddress = $_SERVER['HTTP_FORWARDED'];
        else if (isset($_SERVER['REMOTE_ADDR']))
            $ipaddress = $_SERVER['REMOTE_ADDR'];
        else
            $ipaddress = $request->ip();

        return $ipaddress; // it will return the server IP if the client IP is not found using this method.
    }


    private function generateRandomString($n)
    {

        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

        $randomString = '';
        for ($i = 0; $i < $n; $i++) {

            $index = rand(0, strlen($characters) - 1);

            $randomString .= $characters[$index];
        }

        return $randomString;
    }

    public function token($request, $credentials = [])
    {
        $key = base64_decode(config('SsoConfig.main.KEY'));
        $fromKey = $key;
        $cipher = "AES-256-CBC"; //or AES-128-CBC if you prefer
        $credentials_string = serialize($credentials);

        try {
            //Create two encrypters using different keys for each
            $encrypterFrom = new Encrypter($fromKey, $cipher);
            $token = $request->token ?? $encrypterFrom->encryptString($request->string ?? $credentials_string);
            $decryptedFromString = $encrypterFrom->decryptString($token);
            $decryptedFromString = unserialize($decryptedFromString);

            $return['token'] = $token;
            $return['decryptedFromString'] = $decryptedFromString;
            $return['encrypterFrom'] = $encrypterFrom;
        } catch (\Exception $e) {

            $return = false;
        }
        return $return;
    }

    public function forgot(Request $request)
    {

        $data = $request->all();
        $data['app_url'] = url('/');
        // dd($data);

        $response = Http::timeout(config('SsoConfig.curl.TIMEOUT', 30))->withOptions([
            'verify' => config('SsoConfig.curl.VERIFY', false),
        ])->post(config('SsoConfig.main.URL', url('/')) . 'forgot_password', $data);


        Log::info('user: sys url: ' . url()->current() . ' message: SSO forgot request :' . json_encode($data));

        if ($response->ok()) {
            $data = $response->object();
            $respond =  self::ssoRespond($response);
        } else {
            $data = $response->object();
            $respond = false;
        }

        Log::info('user: sys url: ' . url()->current() . ' message: SSO forgot respond :' . json_encode($data));

        return $respond;
    }

    public function reset(Request $request)
    {
        $data = $request->all();
        // dd($data, config('SsoConfig.main.URL', url('/')) . 'forgot_password');
        $response = Http::timeout(config('SsoConfig.curl.TIMEOUT', 30))->withOptions([
            'verify' => config('SsoConfig.curl.VERIFY', false),
        ])->post(config('SsoConfig.main.URL', url('/')) . 'update_password', $data);

        Log::info('user: sys url: ' . url()->current() . ' message: SSO login request :' . json_encode($data));

        if ($response->ok()) {
            $token = $data['token'];
            $email = $data['email'];
            $user = user::where('email', $email)->first();
            if ($request->hasSession()) {
                $request->session()->put('auth.token', $token);
                $request->session()->put('auth.user', $user);
            }
            $data = $response->object();
            $respond =  self::ssoRespond($response);
        } else {
            $data = $response->object();
            $respond = false;
        }

        Log::info('user: sys url: ' . url()->current() . ' message: SSO login respond :' . json_encode($data));

        // dd( $response->body());
        return $respond;
    }

    public function auth(Request $request, $credentials = [])
    {
        $data = $request->all();
        /*internal cek DB user by token user id ada bug kalo user_status tidak sync ke sso*/
        $token = $request->token ? self::sessionSet($request->token) : false;
        // dd($token);
        // $this->auth($request,['email'=>'2','password'=>2]);
        // dd($credentials);

        $email = $data['email'];
        $user = user::where('email', $email)->first();
        if ($request->hasSession()) {
            $request->session()->put('auth.user', $user);
        }

        if (empty($token)) {

            $credentials = !empty($credentials) ? $credentials : $request->all();
            extract($credentials);
            $rules = array(
                'email' => "required|min:5",
                'password'  => "required|min:3|max:30",
            );

            // $request_all = $request->all();
            $request_all['email'] = @$email;
            $request_all['password'] = @$password;

            // self::validator($request_all, $rules);


            $data['app_code'] = config('SsoConfig.main.APP_CODE', 'APP01');
            $data['email'] = $email;
            $data['password'] = $password;
            if ($token) {
                $data['token'] = $token;
            }
            try {
                $response = Http::timeout(config('SsoConfig.curl.TIMEOUT', 30))->withOptions([
                    'verify' => config('SsoConfig.curl.VERIFY', false),
                ])->post(config('SsoConfig.main.URL', url('/')) . 'auth_login', $data);
            } catch (\Exception $e) {
                Log::info('user: sys url: ' . url()->current() . ' message:' . $e->getMessage());
                return null;
            }

            $data['password'] = '******';
            Log::info('user: sys url: ' . url()->current() . ' message: SSO login request :' . json_encode($data));

            if ($response->ok()) {
                $data = $response->object();
                if ($data->code == '200') {
                    $token =  $data->data->token;
                    $request->session()->put('auth.token', $token);
                }
                $respond =  self::ssoRespond($response);
            } else {
                $data = $response->object();
                $respond = false;
            }

            Log::info('user: sys url: ' . url()->current() . ' message: SSO login respond :' . json_encode($data));

            // dd( $response->body());
            return $respond;
        } else {
            $request->session()->put('auth.token', $token);
            return $token;
        }
    }


    public function cobaCurl()
    {
        $data['email'] = 'bagas.setyonugroho@meindo.com';
        $data['password'] = 'bagas.setyonugroho@meindo.com';
        $response = Http::timeout(config('SsoConfig.curl.TIMEOUT', 30))->withOptions([
            'verify' => config('SsoConfig.curl.VERIFY', false),
        ])->post(config('SsoConfig.main.URL', url('/')) . '/auth_login', $data);

        if ($response->ok()) {
            $data = $response->body();
        }
        Log::info("cobaCurl::" . $data);
        return $data;
    }


    public function setPasswordSso($request)
    {

        $password =  $request->password;
        $token = $request->session()->get('auth.token');

        $data['password'] = $password;
        if ($token) {
            $data['token'] = $token;
        }
        $sso_cek = Http::timeout(config('SsoConfig.curl.TIMEOUT', 30))->withOptions([
            'verify' => config('SsoConfig.curl.VERIFY', false),
        ])->post(config('SsoConfig.main.URL', url('/')) . 'set_password', $data);

        $sso_respond = $sso_cek->object();
        if ($sso_respond->status == 'sukses') {
            $respon = [
                'success' => true,
                'message' => 'Password changed successfully',
            ];
            $code = 200;
        } else {
            $respon = [
                'success' => false,
                'message' => 'Password changed failed',
                'errors' => $sso_respond->data
            ];
            $code = 401;
        }
        $return['respon'] = $respon;
        $return['code'] = $code;
        return $return;
    }


    public function sessionSet($token)
    {
        try {
            $request = new Request([
                'token'   => $token,
            ]);
            $token = $request->token ? self::token($request) : false;
            $user = @(object)$token['decryptedFromString'];
        } catch (\Exception $e) {
            $data['status'] =   'gagal';
            $data['code'] =   101;
            $data['data'] =   $e->getMessage();
            return self::setOutput($data);
        }

        $route = 'home';
        if ($user) {
            $loginbyId = user::where('email', $user->email)->first();
            $user_id =  $loginbyId->id ?? null;
            // Manually Logging a user (Here is successfully recieve the user id)
            $loggedInUser = Auth::loginUsingId($user_id);
            // dd($loggedInUser);
            if (!$loggedInUser || $loggedInUser->is_active == 0) {

                if (!$loggedInUser) {
                    // $data['id'] = $user->id;
                    $data['name'] = $user->name;
                    $data['email'] = $user->email;
                    $data['is_active'] = $user->is_active;
                    $data['password'] = \Hash::make($request->password);
                    // $register = new RegisterController;
                    $create_user = self::create($data);
                    $user_id =  $create_user->id;
                    Auth::loginUsingId($user_id);
                } else {
                    //user inactive
                    $response = 'Please contact the administrator';
                    abort(403, $response);
                }
            }

            // $request->setLaravelSession(session()); //fix kalo session ga kedetek
            if ($request->hasSession()) {
                $request->session()->put('auth.token', $request->token);
                $request->session()->put('auth.user', $user);
            } else {
                return 'no session';
            }
            $redirectTo = '/' . $route;
            // dd($redirectTo,$loggedInUser->toArray(),1);
            return redirect($redirectTo);
        } else {
            $data['status'] =   'gagal';
            $data['code'] =   101;
            $data['data'] =   'Single SignOn: User Cannot be Signed In';
            return self::setOutput($data);
        }
    }

    public function sessionCek(Request $request)
    {
        $user = Auth::check();
        if ($user) {
            $data['data'] =   Auth::user()->toArray();
        } else {
            $data['status'] =   'gagal';
            $data['code'] =   101;
            $data['data'] =   'Single SignOn: User not Signed In';
        }
        return self::setOutput($data);
    }

    public function sessionUnset($token)
    {
        dd('ada bug karena ganti auto login pakek email, solve cari id by email untuk dapat id');
        try {

            $request = new Request();
            $request['token'] = $token;
            $token = self::token($request);
            // dd($request->all(), $token);
            $user_id = $token['decryptedFromString'];
            // $user_id =  $token ? Crypt::decryptString($token) : null;
        } catch (\Exception $e) {
            $data['status'] =   'gagal';
            $data['code'] =   101;
            $data['data'] =   $e->getMessage();
            return self::setOutput($data);
        }
        // dd($user_id);

        if (Auth::id() == $user_id) {
            $route = 'login';
            $session = session::where('user_id', $user_id)->delete();
            $redirectTo = '/' . $route;
        } else {
            $redirectTo = '/';
        }
        return redirect($redirectTo);
    }

    function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
    }
}
