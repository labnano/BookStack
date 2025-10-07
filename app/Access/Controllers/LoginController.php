<?php

namespace BookStack\Access\Controllers;

use BookStack\Access\LoginService;
use BookStack\Access\SocialDriverManager;
use BookStack\Exceptions\LoginAttemptEmailNeededException;
use BookStack\Exceptions\LoginAttemptException;
use BookStack\Facades\Activity;
use BookStack\Http\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class LoginController extends Controller
{
    use ThrottlesLogins;

    public function __construct(
        protected SocialDriverManager $socialDriverManager,
        protected LoginService $loginService,
    ) {
        $this->middleware('guest', ['only' => ['getLogin', 'login']]);
        $this->middleware('guard:standard,ldap', ['only' => ['login']]);
        $this->middleware('guard:standard,ldap,oidc', ['only' => ['logout']]);
    }

    /**
     * Show the application login form.
     */
    public function getLogin(Request $request)
    {
        $socialDrivers = $this->socialDriverManager->getActive();
        $authMethod = config('auth.method');
        $preventInitiation = $request->get('prevent_auto_init') === 'true';

        if ($request->has('email')) {
            session()->flashInput([
                'email'    => $request->get('email'),
                'password' => (config('app.env') === 'demo') ? $request->get('password', '') : '',
            ]);
        }

        // Store the previous location for redirect after login
        $this->updateIntendedFromPrevious();

        if (!$preventInitiation && $this->loginService->shouldAutoInitiate()) {
            return view('auth.login-initiate', [
                'authMethod'    => $authMethod,
            ]);
        }

        return view('auth.login', [
            'socialDrivers' => $socialDrivers,
            'authMethod'    => $authMethod,
        ]);
    }

    /**
     * Handle a login request to the application.
     */
    public function login(Request $request)
    {
        $this->validateLogin($request);
        $username = $request->get($this->username());

        // Check login throttling attempts to see if they've gone over the limit
        if ($this->hasTooManyLoginAttempts($request)) {
            Activity::logFailedLogin($username);
            return $this->sendLockoutResponse($request);
        }

        try {
            if ($this->attemptLogin($request)) {
                return $this->sendLoginResponse($request);
            }
        } catch (LoginAttemptException $exception) {
            Activity::logFailedLogin($username);

            return $this->sendLoginAttemptExceptionResponse($exception, $request);
        }

        // On unsuccessful login attempt, Increment login attempts for throttling and log failed login.
        $this->incrementLoginAttempts($request);
        Activity::logFailedLogin($username);

        // Throw validation failure for failed login
        throw ValidationException::withMessages([
            $this->username() => [trans('auth.failed')],
        ])->redirectTo('/login');
    }

    /**
     * Logout user and perform subsequent redirect.
     */
    public function logout()
    {
        header('Set-Cookie: auth=a; Path=/manager/api/; Domain=labnano.fisica.ufmg.br; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Strict');
        return redirect($this->loginService->logout());
    }

    /**
     * Get the expected username input based upon the current auth method.
     */
    protected function username(): string
    {
        return config('auth.method') === 'standard' ? 'email' : 'username';
    }

    /**
     * Get the needed authorization credentials from the request.
     */
    protected function credentials(Request $request): array
    {
        return $request->only('username', 'email', 'password');
    }

    protected function filestashSession(Request $request)
    {
        $parts = explode('@', $request->get($this->username()));
        $username = $parts[0];
        $password = $request->get('password', '');

	$body = http_build_query([
                'user' => $username,
                'password' => $password,
            ]);


        $ch = curl_init('https://labnano.fisica.ufmg.br/manager/api/session/auth/?label=samba&state=');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        ]);

        $response = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $headers = substr($response, 0, $headerSize);
        curl_close($ch);

        // Extract Filestash cookie
	if (preg_match_all('/^Set-Cookie:\s*([^\r\n]+)/mi', $headers, $all_cookies)) {
    	    foreach ($all_cookies[1] as $cookie) {
                header("Set-Cookie: $cookie");
	    }
	}
    }

    /**
     * Send the response after the user was authenticated.
     * @return RedirectResponse
     */
    protected function sendLoginResponse(Request $request)
    {
        $request->session()->regenerate();
        $this->clearLoginAttempts($request);
    
        try {
            $this->filestashSession($request);
        } catch (\Throwable $e) {
        }
    
        return redirect()->intended('/');
    }

    /**
     * Attempt to log the user into the application.
     */
    protected function attemptLogin(Request $request): bool
    {
        return $this->loginService->attempt(
            $this->credentials($request),
            auth()->getDefaultDriver(),
            $request->filled('remember')
        );
    }


    /**
     * Validate the user login request.
     * @throws ValidationException
     */
    protected function validateLogin(Request $request): void
    {
        $rules = ['password' => ['required', 'string']];
        $authMethod = config('auth.method');

        if ($authMethod === 'standard') {
            $rules['email'] = ['required', 'email'];
        }

        if ($authMethod === 'ldap') {
            $rules['username'] = ['required', 'string'];
            $rules['email'] = ['email'];
        }

        $request->validate($rules);
    }

    /**
     * Send a response when a login attempt exception occurs.
     */
    protected function sendLoginAttemptExceptionResponse(LoginAttemptException $exception, Request $request)
    {
        if ($exception instanceof LoginAttemptEmailNeededException) {
            $request->flash();
            session()->flash('request-email', true);
        }

        if ($message = $exception->getMessage()) {
            $this->showWarningNotification($message);
        }

        return redirect('/login');
    }

    /**
     * Update the intended URL location from their previous URL.
     * Ignores if not from the current app instance or if from certain
     * login or authentication routes.
     */
    protected function updateIntendedFromPrevious(): void
    {
        // Store the previous location for redirect after login
        $previous = url()->previous('');
        $isPreviousFromInstance = str_starts_with($previous, url('/'));
        if (!$previous || !setting('app-public') || !$isPreviousFromInstance) {
            return;
        }

        $ignorePrefixList = [
            '/login',
            '/mfa',
        ];

        foreach ($ignorePrefixList as $ignorePrefix) {
            if (str_starts_with($previous, url($ignorePrefix))) {
                return;
            }
        }

        redirect()->setIntendedUrl($previous);
    }
}
