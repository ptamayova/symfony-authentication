<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CustomCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;

class LoginFormAuthenticator extends AbstractAuthenticator
{
    private UserRepository $userRepository;
    private RouterInterface $routerInterface;

    public function __construct(
        UserRepository $userRepository,
        RouterInterface $routerInterface
    )
    {
        $this->userRepository = $userRepository;
        $this->routerInterface = $routerInterface;
    }

    /*
     * Defines which route should respond to authentication requests.
     */
    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'app_login' && $request->isMethod('POST');
    }

    /*
     * Authenticates a user with credentials using Badges.
     * */
    public function authenticate(Request $request): PassportInterface
    {
        $email = $request->request->get('email');
        $password = $request->request->get('password');

        if (!$email || !$password) {
            throw new AuthenticationException('Username or password is missing.');
        }

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($password),
            [
                new RememberMeBadge(),
                new CsrfTokenBadge(
                    'authenticate',
                    $request->request->get('_csrf_token')
                )
            ]
        );
    }

    /*
     * Responds to a successful authentication attempt
     * */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse(
            $this->routerInterface->generate('app_homepage')
        );
    }

    /*
     * Responds to a failed authentication attempt
     * */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse(
            $this->routerInterface->generate('app_login')
        );
    }

//    public function start(Request $request, AuthenticationException $authException = null): Response
//    {
//        /*
//         * If you would like this class to control what happens when an anonymous user accesses a
//         * protected page (e.g. redirect to /login), uncomment this method and make this class
//         * implement Symfony\Component\Security\Http\EntryPoint\AuthenticationEntrypointInterface.
//         *
//         * For more details, see https://symfony.com/doc/current/security/experimental_authenticators.html#configuring-the-authentication-entry-point
//         */
//    }
}
