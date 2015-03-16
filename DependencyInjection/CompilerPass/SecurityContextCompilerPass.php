<?php

namespace AlexDpy\AclBundle\DependencyInjection\CompilerPass;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class SecurityContextCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->has('security.token_storage')) {
            $this->replaceArgument(
                $container->getDefinition('alex_dpy_acl.acl_identifier'),
                'security.token_storage',
                'security.context'
            );
        }

        if (!$container->has('security.authorization_checker')) {
            $this->replaceArgument(
                $container->getDefinition('alex_dpy_acl.acl_checker'),
                'security.authorization_checker',
                'security.context'
            );
        }
    }

    /**
     * @param Definition $definition
     * @param string     $oldArgument
     * @param string     $newArgument
     */
    private function replaceArgument(Definition $definition, $oldArgument, $newArgument)
    {
        $newArguments = [];

        foreach ($definition->getArguments() as $argument) {
            if ($oldArgument === (string) $argument) {
                $newArguments[] = new Reference($newArgument);
            } else {
                $newArguments[] = $argument;
            }
        }

        $definition->setArguments($newArguments);
    }
}
