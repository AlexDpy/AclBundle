<?php

namespace AlexDpy\AclBundle\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class FakeRoleToken extends AbstractToken
{
    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return '';
    }
}
 