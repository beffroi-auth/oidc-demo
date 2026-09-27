<?php

declare(strict_types=1);

namespace App\Ladder;

/**
 * The ladder of demonstration clients (heidi#201), from the plainest client to the whole of FAPI 2.0.
 *
 * One rung is one registration on the provider and one firewall here. A rung adds one thing to the one
 * before it, and what it adds is what the provider grew during the spike: how the client authenticates,
 * which way the authorization response comes back, what shape its access token has, and what a logout
 * reaches. Nothing of the provider changes from one rung to the next: what changes is what the client
 * registered and what it asks for.
 */
final class Rungs
{
    /**
     * @var array<string, array{name: string, firewall: string, client: string, adds: string, capabilities: array<string, string>}>
     */
    public const RUNGS = [
        'basic' => [
            'name' => 'Basique',
            'firewall' => 'ladder_basic',
            'client' => 'oidc-demo',
            'adds' => 'Le point de départ : tout passe par la barre d\'adresse du navigateur.',
            'capabilities' => [
                'Authentification du client' => 'client_secret_basic, le secret dans l\'en-tête HTTP Basic',
                'Requête d\'autorisation' => 'en clair dans la query, avec PKCE S256',
                'Réponse d\'autorisation' => 'code, state et iss dans la query (RFC 9207)',
                'Jetons' => 'at+jwt signé, vérifié hors ligne contre le JWK Set',
                'Déconnexion' => 'RP-Initiated Logout, aller-retour par le navigateur',
            ],
        ],
        'opaque' => [
            'name' => 'Jeton opaque',
            'firewall' => 'ladder_opaque',
            'client' => 'oidc-demo-opaque',
            'adds' => 'Le même client, un access token qui ne dit rien à qui le lit.',
            'capabilities' => [
                'Authentification du client' => 'client_secret_basic',
                'Requête d\'autorisation' => 'en clair dans la query, avec PKCE S256',
                'Réponse d\'autorisation' => 'code, state et iss dans la query',
                'Jetons' => 'access token opaque : un serveur de ressources demande au fournisseur ce qu\'il est (RFC 7662), à chaque requête',
                'Déconnexion' => 'RP-Initiated Logout',
            ],
        ],
        'form-post' => [
            'name' => 'Réponse postée',
            'firewall' => 'ladder_form_post',
            'client' => 'demo-form-post',
            'adds' => 'La réponse ne passe plus par l\'URL : le fournisseur la poste.',
            'capabilities' => [
                'Authentification du client' => 'client_secret_post, le secret dans le corps',
                'Requête d\'autorisation' => 'en clair dans la query, avec PKCE S256',
                'Réponse d\'autorisation' => 'form_post : une page auto-postée, rien dans l\'historique du navigateur ni dans les journaux',
                'Jetons' => 'at+jwt signé',
                'Déconnexion' => 'RP-Initiated Logout',
            ],
        ],
        'key' => [
            'name' => 'Clé du client',
            'firewall' => 'ladder_key',
            'client' => 'demo-key',
            'adds' => 'Le client ne partage plus de secret : il prouve une clé, et il est prévenu des déconnexions.',
            'capabilities' => [
                'Authentification du client' => 'private_key_jwt : une assertion signée ES256 (RFC 7523)',
                'Requête d\'autorisation' => 'en clair dans la query, avec PKCE S256',
                'Réponse d\'autorisation' => 'code, state et iss dans la query',
                'Jetons' => 'at+jwt signé',
                'Déconnexion' => 'RP-Initiated Logout, et le canal avant : la page de déconnexion du fournisseur charge une URI de ce client dans un cadre (Front-Channel Logout 1.0)',
            ],
        ],
        'rar' => [
            'name' => 'Ce qu\'il demande',
            'firewall' => 'ladder_rar',
            'client' => 'demo-rar',
            'adds' => 'Le client ne demande plus une sorte de chose : il demande ce qu\'il peut faire, à quoi, et jusqu\'où.',
            'capabilities' => [
                'Authentification du client' => 'client_secret_basic',
                'Requête d\'autorisation' => 'en clair dans la query, avec PKCE S256, et un authorization_details (RFC 9396) qu\'oidc_login envoie par authorization_params',
                'Consentement' => 'la page du fournisseur dit le détail en mots, dans la langue du lecteur : la facture nommée, ce qui peut lui être fait, et le montant le plus élevé qui peut bouger',
                'Réponse d\'autorisation' => 'code, state et iss dans la query',
                'Jetons' => 'at+jwt portant authorization_details tel que la sorte du détail l\'a construit ; la réponse du token endpoint dit ce qu\'elle a accordé, et l\'introspection le rend',
                'Déconnexion' => 'RP-Initiated Logout',
            ],
        ],
        'fapi' => [
            'name' => 'FAPI 2.0',
            'firewall' => 'ladder_fapi',
            'client' => 'demo-fapi',
            'adds' => 'Plus rien ne passe par le navigateur en clair : la requête est poussée et signée, la réponse est signée, le jeton est lié à une clé, et les documents sont chiffrés pour ce client.',
            'capabilities' => [
                'Authentification du client' => 'private_key_jwt (RFC 7523)',
                'Requête d\'autorisation' => 'poussée au point /par (RFC 9126) et signée comme objet de requête (RFC 9101) : le navigateur ne porte que client_id et request_uri',
                'Réponse d\'autorisation' => 'JARM : un seul paramètre "response", un JWT signé par le fournisseur',
                'Jetons' => 'at+jwt lié par DPoP (RFC 9449) : cnf.jkt, et une preuve signée à chaque requête ; ID token et UserInfo signés puis chiffrés pour la clé de ce client',
                'Déconnexion' => 'RP-Initiated Logout et canal avant',
            ],
        ],
    ];

    /**
     * @return array{name: string, firewall: string, client: string, adds: string, capabilities: array<string, string>}
     */
    public static function of(string $slug): array
    {
        return self::RUNGS[$slug] ?? throw new \InvalidArgumentException(sprintf('No rung "%s" on the ladder.', $slug));
    }

    /**
     * The slugs, as a route requirement writes them.
     */
    public static function pattern(): string
    {
        return implode('|', array_keys(self::RUNGS));
    }
}
