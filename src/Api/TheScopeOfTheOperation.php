<?php

namespace App\Api;

use ApiPlatform\Metadata\HttpOperation;
use Symfony\Component\HttpFoundation\JsonResponse;
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
    /**
     * The problem type of this refusal, which is the section that defines it: a client reads the
     * challenge, and whoever reads the body is sent to what the challenge means.
     */
    private const string PROBLEM_TYPE = 'https://datatracker.ietf.org/doc/html/rfc6750#section-3.1';

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
        $challenge = $this->insufficientScope->handle($request, $denial);
        if (null === $challenge) {
            return null;
        }

        return $this->withTheDocumentOfTheRefusal($challenge, ScopesOfTheOperation::of($operation));
    }

    /**
     * The same refusal, with a body in the media type the other refusals of this API answer in
     * (RFC 9457): the challenge is what a client acts on, and a page, a log or a reader of this
     * demonstration gets a document saying the same thing rather than a 403 that says nothing.
     *
     * The scope it names is read from the operation, as the challenge was, and not from the header
     * this just wrote: two readings of one place, never a parse of our own answer.
     *
     * @param list<string> $scopes
     */
    private function withTheDocumentOfTheRefusal(Response $challenge, array $scopes): Response
    {
        $document = new JsonResponse([
            'type' => self::PROBLEM_TYPE,
            'title' => 'insufficient_scope',
            'status' => Response::HTTP_FORBIDDEN,
            'detail' => sprintf(
                'This operation requires the scope "%s", which the access token was not granted.',
                implode(' ', $scopes),
            ),
        ], Response::HTTP_FORBIDDEN);
        $document->headers->set('Content-Type', 'application/problem+json');
        $document->headers->set('WWW-Authenticate', $challenge->headers->all('WWW-Authenticate'));

        return $document;
    }
}
