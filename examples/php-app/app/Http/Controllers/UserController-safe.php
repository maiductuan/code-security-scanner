<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserControllerSafe extends Controller
{
    public function show(Request $request)
    {
        $id = $request->query('id');
        // Safe: parameterized query
        $users = DB::select("SELECT * FROM users WHERE id = ?", [$id]);
        
        return view('user-safe', ['username' => $request->query('username')]);
    }
}
