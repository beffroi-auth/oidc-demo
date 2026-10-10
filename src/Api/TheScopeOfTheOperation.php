<?php

namespace App\Api;

use ApiPlatform\Metadata\HttpOperation;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;
use Symfony\Component\Security\Http\Authorization\InsufficientScopeAccessDeniedHandler;

/**
 * What answers a request this API refused for a scope it was not granted: the 403 and the
 * "insufficient_scope" challenge of RFC 6750 section 3.1, naming the scope that is missing.
 *
 * Symfony answers that by itself when the denial comes from an access control rule, reading the required
 * scopes off the attributes of the denial (InsufficientScopeAccessDeniedHandler). API Platform denies
 * otherwise: the "security" of an operation is an expression it evaluates, and what comes back is a
 * boolean, so the denial carries no attribute and nothing names the scope any more.
 *
 * The scope is therefore read back where it is written, the operation itself (ScopesOfTheOperation),
 * which is also where the documentation of the API reads it (ScopesInTheDocument). One place: an
 * operation that names its scope gets the challenge of that scope, and a denial that has nothing to do
 * with a scope is left alone.
 */
final readonly class TheScopeOfTheOperation implements AccessDeniedHandlerInterface
{
    private InsufficientScopeAccessDeniedHandler $insufficientScope;

    public function __construct(string $realm)
    {
        $this->insufficientScope = new InsufficientScopeAccessDeniedHandler($realm);
    }

    public function handle(Request $request, AccessDeniedException $accessDeniedException): ?Response
    {
        $operation = $request->attributes->get('_api_operation');
        if (!$operation instanceof HttpOperation) {
            return null;
        }

        $attributes = ScopesOfTheOperation::attributesOf($operation);
        if ([] === $attributes) {
            return null;
        }

        $denial = new AccessDeniedException($accessDeniedException->getMessage(), $accessDeniedException);
        $denial->setAttributes($attributes);

        return $this->insufficientScope->handle($request, $denial);
    }
}
