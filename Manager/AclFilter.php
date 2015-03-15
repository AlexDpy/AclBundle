<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Permission\PermissionMapInterface;
use AlexDpy\AclBundle\Permission\PermissionMapWrapper;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Query\QueryBuilder as DBALQueryBuilder;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface as SymfonyPermissionMapInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclFilter
{
    /**
     * @var AclIdentifierInterface
     */
    protected $aclIdentifier;

    /**
     * @var RoleHierarchyInterface
     */
    protected $roleHierarchy;

    /**
     * @var PermissionMapInterface
     */
    protected $permissionMap;

    /**
     * @var string
     */
    protected $aclWalker;

    /**
     * @param AclIdentifierInterface $aclIdentifier
     * @param RoleHierarchyInterface $roleHierarchy
     */
    public function __construct(AclIdentifierInterface $aclIdentifier, RoleHierarchyInterface $roleHierarchy)
    {
        $this->aclIdentifier = $aclIdentifier;
        $this->roleHierarchy = $roleHierarchy;
    }


    /**
     * @param SymfonyPermissionMapInterface $permissionMap
     */
    public function setPermissionMap(SymfonyPermissionMapInterface $permissionMap)
    {
        if (!$permissionMap instanceof PermissionMapInterface) {
            $permissionMap = new PermissionMapWrapper($permissionMap);
        }

        $this->permissionMap = $permissionMap;
    }

    /**
     * @param string $aclWalker
     */
    public function setAclWalker($aclWalker)
    {
        $this->aclWalker = $aclWalker;
    }

    /**
     * @param DBALQueryBuilder|QueryBuilder $queryBuilder
     * @param string                        $permission
     * @param string                        $oidClass
     * @param string                        $oidReference
     * @param UserInterface                 $user
     *
     * @return Query|DBALQueryBuilder
     * @throws \Exception
     */
    public function apply($queryBuilder, $permission, $oidClass, $oidReference, UserInterface $user)
    {
        if ($queryBuilder instanceof DBALQueryBuilder) {
            $connection = $queryBuilder->getConnection();
        } elseif ($queryBuilder instanceof QueryBuilder) {
            $connection = $queryBuilder->getEntityManager()->getConnection();
        }else {
            throw new \Exception();
        }

        //@TODO use permissionMap->getMasks($permission, $object) to generate the requiredMask
        $requiredMask = $this->permissionMap->getMaskBuilder()->getMask($permission);

        $subQuery = <<<SQL
SELECT acl_o.object_identifier
FROM acl_object_identities acl_o
INNER JOIN acl_classes acl_c ON acl_o.class_id = acl_c.id AND acl_c.class_type = {$connection->quote($oidClass)}
LEFT JOIN acl_entries acl_e ON acl_o.class_id = acl_e.class_id
  AND (acl_o.id = acl_e.object_identity_id OR acl_e.object_identity_id IS NULL)
LEFT JOIN acl_security_identities acl_s ON acl_e.security_identity_id = acl_s.id
WHERE acl_o.object_identifier = {$oidReference}
  AND {$this->getSecurityIdentitiesWhereClause($connection, $user)}
  AND acl_e.granting = 1 AND (
    (acl_e.granting_strategy = {$connection->quote(PermissionGrantingStrategy::ALL)} AND {$requiredMask} = (acl_e.mask & {$requiredMask}))
    OR (acl_e.granting_strategy = {$connection->quote(PermissionGrantingStrategy::ANY)} AND 0 != (acl_e.mask & {$requiredMask}))
    OR (acl_e.granting_strategy = {$connection->quote(PermissionGrantingStrategy::EQUAL)} AND {$requiredMask} = acl_e.mask)
  )
SQL;

        if ($queryBuilder instanceof QueryBuilder) {
            $query = $queryBuilder->getQuery();
            $query->setHint('acl_filter_sub_query', $subQuery);
            $query->setHint('acl_filter_oid_reference', $oidReference);
            $query->setHint(Query::HINT_CUSTOM_OUTPUT_WALKER, $this->aclWalker);

            return $query;
        }

        $queryBuilder->andWhere($oidReference . ' IN (' . $subQuery . ')');

        return $queryBuilder;
    }

    /**
     * Get security identifiers associated with specified identity
     *
     * @param Connection    $connection
     * @param UserInterface $user
     *
     * @return string
     */
    private function getSecurityIdentitiesWhereClause(Connection $connection, UserInterface $user)
    {
        $userSid = $this->aclIdentifier->getUserSecurityIdentity($user);
        $sql = '(acl_s.username = 1 AND acl_s.identifier = '
            . $connection->quote($userSid->getClass() . '-' .$userSid->getUsername()) . ')';

        $roles = $this->roleHierarchy->getReachableRoles(array_map(function ($role) {
            if (!$role instanceof Role) {
                $role = new Role($role);
            }

            return $role;
        }, $user->getRoles()));

        if (!empty($roles)) {
            $quotedRoles = array_map(function (RoleInterface $role) use ($connection) {
                return $connection->quote($role->getRole());
            }, $roles);

            $sql .= ' OR (acl_s.username = 0 AND acl_s.identifier IN (' . implode(', ', $quotedRoles) . '))';
        }

        return '(' . $sql . ')';
    }
}
