<?php

namespace App\Http\Controllers\Web;

use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Validation\Rules\Password;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Artisan;
use App\Http\Controllers\Controller;
use App\Models\User;

class UsersController extends Controller
{
    use ValidatesRequests;

    /**
     * Display a list of users.
     */
    public function list(Request $request)
    {
        if (!auth()->user()->hasPermissionTo('show_users')) abort(401);

        $users = User::when($request->keywords, function ($query, $keywords) {
            return $query->where("name", "like", "%$keywords%");
        })->get();

        return view('users.list', compact('users'));
    }

    /**
     * Show registration form.
     */
    public function register()
    {
        return view('users.register');
    }

    /**
     * Handle user registration.
     */
    public function doRegister(Request $request)
    {
        // Validate Input
        $request->validate([
            'name' => ['required', 'string', 'min:5'],
            'email' => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'confirmed', Password::min(8)->numbers()->letters()->mixedCase()->symbols()],
        ]);

        // Create User
        try {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            Log::info('User registered successfully', ['user_id' => $user->id]);

            return redirect('/')->with('success', 'Registration successful!');
        } catch (\Exception $e) {
            Log::error('User registration failed', ['error' => $e->getMessage()]);
            return redirect()->back()->withErrors('Registration failed, please try again.');
        }
    }

    /**
     * Show login form.
     */
    public function login()
    {
        return view('users.login');
    }

    /**
     * Handle user login.
     */
    public function doLogin(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!Auth::attempt($credentials)) {
            return redirect()->back()->withErrors('Invalid login information.');
        }

        Log::info('User logged in', ['user_id' => Auth::id()]);

        return redirect('/');
    }

    /**
     * Handle user logout.
     */
    public function doLogout()
    {
        Auth::logout();
        return redirect('/')->with('success', 'Logged out successfully.');
    }

    /**
     * Show user profile.
     */
    public function profile(User $user = null)
    {
        $user = $user ?? auth()->user();
        if (auth()->id() !== $user->id && !auth()->user()->hasPermissionTo('show_users')) {
            abort(401);
        }

        $permissions = collect($user->permissions)->merge($user->roles->flatMap->permissions);

        return view('users.profile', compact('user', 'permissions'));
    }

    /**
     * Show edit user form.
     */
    public function edit(User $user = null)
    {
        $user = $user ?? auth()->user();
        if (auth()->id() !== $user->id && !auth()->user()->hasPermissionTo('edit_users')) {
            abort(401);
        }

        $roles = Role::all()->map(function ($role) use ($user) {
            $role->taken = $user->hasRole($role->name);
            return $role;
        });

        $permissions = Permission::all()->map(function ($permission) use ($user) {
            $permission->taken = $user->hasPermissionTo($permission->name);
            return $permission;
        });

        return view('users.edit', compact('user', 'roles', 'permissions'));
    }

    /**
     * Update user details.
     */
    public function save(Request $request, User $user)
    {
        if (auth()->id() !== $user->id && !auth()->user()->hasPermissionTo('admin_users')) {
            abort(401);
        }

        $user->update(['name' => $request->name]);

        if (auth()->user()->hasPermissionTo('admin_users')) {
            $user->syncRoles($request->roles);
            $user->syncPermissions($request->permissions);
            Artisan::call('cache:clear');
        }

        return redirect(route('profile', ['user' => $user->id]));
    }

    /**
     * Delete a user.
     */
    public function delete(User $user)
    {
        if (!auth()->user()->hasPermissionTo('delete_users')) {
            abort(401);
        }

        $user->delete();

        return redirect()->route('users');
    }

    /**
     * Show edit password form.
     */
    public function editPassword(User $user = null)
    {
        $user = $user ?? auth()->user();
        if (auth()->id() !== $user->id && !auth()->user()->hasPermissionTo('edit_users')) {
            abort(401);
        }

        return view('users.edit_password', compact('user'));
    }

    /**
     * Update user password.
     */
    public function savePassword(Request $request, User $user)
    {
        if (auth()->id() === $user->id) {
            $request->validate([
                'password' => ['required', 'confirmed', Password::min(8)->numbers()->letters()->mixedCase()->symbols()],
            ]);

            if (!Auth::attempt(['email' => $user->email, 'password' => $request->old_password])) {
                Auth::logout();
                return redirect('/')->withErrors('Old password is incorrect.');
            }
        } else if (!auth()->user()->hasPermissionTo('edit_users')) {
            abort(401);
        }

        $user->update(['password' => Hash::make($request->password)]);

        return redirect(route('profile', ['user' => $user->id]))->with('success', 'Password updated successfully.');
    }
}
