<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function show(Request $request)
    {
        $id = $request->query('id');
        // SQL Injection (concatenation in select)
        $users = DB::select("SELECT * FROM users WHERE id = " . $id);
        
        return view('user', ['username' => $request->query('username')]);
    }
}
