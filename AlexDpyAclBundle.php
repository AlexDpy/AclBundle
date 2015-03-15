<?php

namespace AlexDpy\AclBundle;

use AlexDpy\AclBundle\DependencyInjection\CompilerPass\OrmCompilerPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class AlexDpyAclBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        $container->addCompilerPass(new OrmCompilerPass());
    }
}
