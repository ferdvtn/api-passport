<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validate = Validator::make ($request->all(), [
            'name' => 'required|min:3|max:255',
            'email' => 'required|min:3|max:255|email|unique:users,email',
            'password' => 'required|min:3|max:255|confirmed',
            'password_confirmation' => 'required|min:3|max:255',
        ]);

        if ($validate->fails()) {
            $data = [
                'status' => false,
                'message' => 'Error validasi input',
                'code' => 400,
                'error' => $validate->errors()
            ];

            return response($data, 400);
        }

        DB::beginTransaction();

        $User = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        
        $token = $User->createToken('auth')->accessToken;
        
        DB::commit();

        $data = [
            'status' => true,
            'message' => 'Create user success',
            'code' => 201,
            'token' => $token
        ];

        return response($data, 201);
        
    }

    public function login(Request $request)
    {
        $validate = Validator::make($request->all(), [
            'email' => 'required|min:3|max:255|email',
            'password' => 'required',
        ]);

        if ($validate->fails()) {
            $data = [
                'status' => false,
                'message' => 'Error validasi input',
                'code' => 400,
                'error' => $validate->errors()
            ];

            return response($data, 400);
        }

        if (Auth::attempt(['email' => $request->email, 'password' => $request->password]))
        {
            $data = [
                'status' => true,
                'token' => Auth::user()->createToken('auth')->accessToken
            ];

            return response($data);

        } else {
            $data = [
                'status' => false,
                'message' => 'User not found'
            ];

            return response($data);

        }
    }

    public function detail(Request $request)
    {
        $User = Auth::user();

        return response($User);
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();

        $data = [
            'status' => true,
            'message' => 'You have been successfully logged out !'
        ];

        return response($data);
    }
}
