<?php

namespace App\Api;

use ApiPlatform\Metadata\HttpOperation;
use ApiPlatform\Metadata\Resource\Factory\ResourceMetadataCollectionFactoryInterface;
use ApiPlatform\Metadata\Resource\ResourceMetadataCollection;
use ApiPlatform\OpenApi\Model\Operation as Documented;
use Symfony\Component\DependencyInjection\Attribute\AsDecorator;

/**
 * What each operation of this API requires, written in the document that describes it: whoever reads
 * /api/v1/docs learns which scope an operation needs before calling it and being refused for it.
 *
 * It is derived from the "security" expression of the operation and never listed beside it
 * (ScopesOfTheOperation), so an operation whose scope changes says the new one, and an operation that
 * requires none says nothing.
 *
 * OpenAPI 3.1 §4.8.30: the scopes are those of the "oauth" scheme, whose flow obtains them; the
 * "bearer" scheme carries a token obtained elsewhere, where the only valid requirement is an empty one.
 * The sentence in the description says the same to whoever reads the page rather than the document.
 */
#[AsDecorator('api_platform.metadata.resource.metadata_collection_factory')]
final readonly class ScopesInTheDocument implements ResourceMetadataCollectionFactoryInterface
{
    public function __construct(
        private ResourceMetadataCollectionFactoryInterface $decorated,
    ) {
    }

    public function create(string $resourceClass): ResourceMetadataCollection
    {
        $collection = $this->decorated->create($resourceClass);

        foreach ($collection as $index => $resource) {
            $operations = $resource->getOperations();
            if (null === $operations) {
                continue;
            }

            foreach ($operations as $name => $operation) {
                if (!$operation instanceof HttpOperation) {
                    continue;
                }

                $scopes = ScopesOfTheOperation::of($operation);
                $documented = $operation->getOpenapi();
                // an operation the document does not describe is left out of it, as it asked
                if ([] === $scopes || false === $documented) {
                    continue;
                }

                $documented = $documented instanceof Documented ? $documented : new Documented();
                $operations->add($name, $operation->withOpenapi(
                    $documented
                        ->withDescription(self::describe($documented->getDescription(), $operation, $scopes))
                        ->withSecurity([['oauth' => $scopes], ['bearer' => []]]),
                ));
            }

            $collection[$index] = $resource->withOperations($operations);
        }

        return $collection;
    }

    /**
     * @param list<string> $scopes
     */
    private static function describe(?string $description, HttpOperation $operation, array $scopes): string
    {
        $sentence = sprintf(
            'The access token has to carry the scope %s.',
            implode(' and ', array_map(static fn (string $scope): string => sprintf('"%s"', $scope), $scopes)),
        );
        $description ??= $operation->getDescription();

        if (null === $description || '' === $description) {
            return $sentence;
        }

        // the description an operation already carries is a sentence of its own, whether or not whoever
        // wrote it ended it
        return rtrim($description, " \t\n.") . '. ' . $sentence;
    }
}
