<?php

namespace AlexDpy\AclBundle\DataCollector\Collector;

use AlexDpy\AclBundle\Manager\AclIdentifierInterface;
use AlexDpy\AclBundle\Manager\AclManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclManagerCollector implements AclManagerInterface
{
    /**
     * @var AclManagerInterface
     */
    private $aclManager;

    /**
     * @var array
     */
    private $managements;

    /**
     * @var AclIdentifierInterface
     */
    private $aclIdentifier;

    /**
     * @param AclManagerInterface $aclManager
     */
    public function __construct(AclManagerInterface $aclManager)
    {
        $aclIdentifierProperty = new \ReflectionProperty('AlexDpy\AclBundle\Manager\AclManager', 'aclIdentifier');
        $aclIdentifierProperty->setAccessible(true);
        $this->aclIdentifier = $aclIdentifierProperty->getValue($aclManager);

        $this->aclManager = $aclManager;
        $this->managements = [];
    }

    /**
     * @param float $startTime
     */
    private function collectManagement($startTime)
    {
        $time = (microtime(true) - $startTime) * 1000;

        $backtrace = debug_backtrace(0, 2)[1];

        $oidType = 'Class' === substr($backtrace['function'], -5)
            ? AclIdentifierInterface::OID_TYPE_CLASS
            : AclIdentifierInterface::OID_TYPE_OBJECT;

        if ('delete' === substr($backtrace['function'], 0, 6)) {
            $permissions = null;
            $oid = $this->aclIdentifier->getObjectIdentity($oidType, $backtrace['args'][0]);
            $sid = null;
            $field = null;
        } else {
            $permissions = $backtrace['args'][0];
            $oid = $this->aclIdentifier->getObjectIdentity($oidType, $backtrace['args'][1]);
            $sid = false !== strpos($backtrace['function'], 'Role')
                ? $this->aclIdentifier->getRoleSecurityIdentity($backtrace['args'][2])
                : $this->aclIdentifier->getUserSecurityIdentity(
                    isset($backtrace['args'][2]) ? $backtrace['args'][2] : null
                );
            $field = isset($backtrace['args'][3]) ? $backtrace['args'][3] : null;
        }

        $this->managements[] = [
            'method' => $backtrace['function'],
            'permissions' => (array) $permissions,
            'oid' => $oid,
            'sid' => $sid,
            'field' => $field,
            'time' => $time
        ];
    }

    /**
     * @return array
     */
    private function getManagements()
    {
        return $this->managements;
    }

    /**
     * {@inheritdoc}
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->grantRoleOnClass($permissions, $class, $role, $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function grantRoleOnObject($permissions, $object, $role, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->grantRoleOnObject($permissions, $object, $role, $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->grantUserOnClass($permissions, $class, $user, $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->grantUserOnObject($permissions, $object, $user , $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnClass($permissions, $class, $role, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->revokeRoleOnClass($permissions, $class, $role, $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->revokeRoleOnObject($permissions, $object, $role, $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->revokeUserOnClass($permissions, $class, $user, $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        $startTime = microtime(true);
        $this->aclManager->revokeUserOnObject($permissions, $object, $user, $field);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForClass($class)
    {
        $startTime = microtime(true);
        $this->aclManager->deleteAclForClass($class);
        $this->collectManagement($startTime);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForObject($object)
    {
        $startTime = microtime(true);
        $this->aclManager->deleteAclForObject($object);
        $this->collectManagement($startTime);
    }

    /**
     * @param $method
     * @param $arguments
     * @return mixed
     */
    public function __call($method, $arguments)
    {
        return call_user_func_array([$this->aclManager, $method], $arguments);
    }
}
