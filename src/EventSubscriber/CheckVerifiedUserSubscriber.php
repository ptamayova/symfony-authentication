<?php

namespace App\EventSubscriber;

use App\Entity\User;
use App\Security\AccountNotVerifiedAuthenticationException;
use Exception;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\UserPassportInterface;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;

class CheckVerifiedUserSubscriber implements EventSubscriberInterface
{
    private RouterInterface $router;

    public function __construct(RouterInterface $router)
    {
        $this->router = $router;
    }

    /**
     * @throws Exception
     */
    public function onCheckPassportEvent(CheckPassportEvent $event)
    {
        $passport = $event->getPassport();
        if (!$passport instanceof UserPassportInterface) {
            throw new Exception('Unexpected passport type');
        }

        $user = $passport->getUser();
        if (!$user instanceof User) {
            throw new Exception('Unexpected user type');
        }

        if (!$user->getIsVerified()) {
            throw new AccountNotVerifiedAuthenticationException();
        }
    }

    public function onLoginFailure(LoginFailureEvent $event)
    {
        if (!$event->getException() instanceof AccountNotVerifiedAuthenticationException) {
            return;
        }

        $response = new RedirectResponse(
            $this->router->generate('app_verify_resend_email')
        );

        $event->setResponse($response);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            CheckPassportEvent::class => ['onCheckPassportEvent', -10],
            LoginFailureEvent::class => 'onLoginFailure',
        ];
    }
}
