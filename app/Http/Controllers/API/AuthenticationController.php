<?php

namespace App\Http\Controllers\API;

use DB;
use Hash;
use Auth;
use Session;
use Carbon\Carbon;
use App\Models\User;
use Laravel\Passport\Token;
use Illuminate\Http\Request;
use Laravel\Passport\RefreshToken;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\AuthorizedAccessToken;

class AuthenticationController extends Controller
{
    /** register new account */
    public function register(Request $request)
    {
        $request->validate([
            'name'     => 'required|min:4',
            'email'     => 'required|string|email|max:255|unique:users',
            'password' => 'required|min:8',
        ]);

        try {
                $dt        = Carbon::now();
                $join_date = $dt->toDayDateTimeString();

                $user = new User();
                $user->name         = $request->name;
                $user->email        = $request->email;
                $user->join_date    = $join_date;
                $user->role_name    = 'User Normal';
                $user->password     = Hash::make($request->password);
                $user->save();
                $data = [];
                $data['response_code']  = '200';
                $data['status']         = 'success';
                $data['message']        = 'success Register';
                return response()->json($data);
            } catch(\Exception $e) {
                \Log::info($e);
                $data = [];
                $data['response_code']  = '401';
                $data['status']         = 'error';
                $data['message']        = 'fail Register';
                return response()->json($data);
            }
    }

    /**
        * Login Req
        */
    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required|string',
            'password' => 'required|string',
        ]);

        try {
                
            $email     = $request->email;
            $password  = $request->password;

            if (Auth::attempt(['email' => $email,'password' => $password])) {

                /** last login update */
                $lastUpdate = [
                    'last_login' => Carbon::now(),
                ];

                User::where('email',$email)->update($lastUpdate);
                /** get session */
                $user = Auth::User();
                Session::put('name', $user->name);
                Session::put('email', $user->email);
                Session::put('user_id', $user->user_id);
                Session::put('join_date', $user->join_date);
                Session::put('last_login', $user->last_login);
                Session::put('phone_number', $user->phone_number);
                Session::put('status', $user->status);
                Session::put('role_name', $user->role_name);
                Session::put('avatar', $user->avatar);
                Session::put('position', $user->position);
                Session::put('department', $user->department);
                $accessToken = $user->createToken($user->email)->accessToken;  
                
                $data = [];
                $data['response_code']  = '200';
                $data['status']         = 'success';
                $data['message']        = 'success Login';
                $data['user_infor']     = $user;
                $data['token']          = $accessToken;
                return response()->json($data);
            } else {
                $data = [];
                $data['response_code']  = '401';
                $data['status']         = 'error';
                $data['message']        = 'Unauthorised';
                return response()->json($data);
            }
        } catch(\Exception $e) {
            \Log::info($e);
            $data = [];
            $data['response_code']  = '401';
            $data['status']         = 'error';
            $data['message']        = 'fail Login';
            return response()->json($data);
        }
    }

    /** user info */
    public function userInfo() 
    {
        try {
            $userDataList = User::latest()->paginate(10);
            $data = [];
            $data['response_code']  = '200';
            $data['status']         = 'success';
            $data['message']        = 'success get user list';
            $data['data_user_list'] = $userDataList;
            return response()->json($data);
        } catch(\Exception $e) {
            \Log::info($e);
            $data = [];
            $data['response_code']  = '400';
            $data['status']         = 'error';
            $data['message']        = 'fail get user list';
            return response()->json($data);
        }
    }

    /** logout */
    public function logOut(Request $request)
    {
        try {
            // Check if the user is authenticated
            if (Auth::check()) {
                // Delete all tokens associated with the authenticated user
                Auth::user()->tokens()->delete();
                
                $data = [
                    'response_code' => '200',
                    'status'        => 'success',
                    'message'       => 'Successfully logged out',
                ];
                return response()->json($data);
            }

            // If user is not authenticated
            return response()->json([
                'response_code' => '401',
                'status'        => 'error',
                'message'       => 'User not authenticated',
            ], 401);
            
        } catch (\Exception $e) {
            // Log the exception and display a generic error message
            \Log::error('Logout error: ' . $e->getMessage());
            return response()->json([
                'response_code' => '500',
                'status'        => 'error',
                'message'       => 'An error occurred while logging out',
            ], 500);
        }
    }
}
