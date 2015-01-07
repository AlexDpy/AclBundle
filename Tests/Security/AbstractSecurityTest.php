<?php

namespace AlexDpy\AclBundle\Tests\Security;

use AlexDpy\AclBundle\Manager\AclCheckerInterface;
use AlexDpy\AclBundle\Manager\AclManagerInterface;
use Doctrine\DBAL\Driver\Connection;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\Security\Acl\Dbal\Schema;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;

class AbstractSecurityTest extends WebTestCase
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @var TokenInterface
     */
    protected $token;

    /**
     * @var Connection
     */
    protected $connection;

    /**
     * @var AclManagerInterface
     */
    protected $aclManager;

    /**
     * @var AclCheckerInterface
     */
    protected $aclChecker;

    /**
     * @var array
     */
    protected $tableNames;

    public function setUp()
    {
        $this->client = static::createClient();
        $this->container = $this->client->getContainer();

        $this->connection = $this->container->get('database_connection');

        if (!class_exists('PDO') || !in_array('sqlite', \PDO::getAvailableDrivers())) {
            $this->markTestSkipped('This test requires SQLite support in your environment.');
        }

        $this->createDB();

        $this->aclManager = $this->container->get('alex_dpy_acl.acl_manager');
        $this->aclChecker = $this->container->get('alex_dpy_acl.acl_checker');
    }

    protected function createDB()
    {
        $this->tableNames = array(
            'oid_table_name' => 'acl_object_identities',
            'oid_ancestors_table_name' => 'acl_object_identity_ancestors',
            'class_table_name' => 'acl_classes',
            'sid_table_name' => 'acl_security_identities',
            'entry_table_name' => 'acl_entries',
        );

        $schema = new Schema($this->tableNames);

        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->exec($sql);
        }
    }

    protected function cleanDB()
    {
        foreach ($this->tableNames as $table) {
            $this->connection->query(sprintf('DROP TABLE %s;', $table));
        }

        $this->createDB();
    }

    /**
     * @param string      $username
     * @param array $roles
     *
     * @return UserInterface
     */
    protected function generateUser($username, Array $roles = ['ROLE_USER'])
    {
        return new User($username, null, $roles);
    }

    /**
     * @param UserInterface $user
     */
    protected function authenticateUser(UserInterface $user)
    {
        $this->token = $this->createToken($user);
        $this->container->get('security.context')->setToken($this->token);
        $this->container->get('security.token_storage')->setToken($this->token);
        $this->assertTrue($this->token->isAuthenticated());
    }

    /**
     * @param UserInterface $user
     *
     * @return UsernamePasswordToken
     */
    protected function createToken(UserInterface $user)
    {
        $token = new UsernamePasswordToken($user, '', 'main', $user->getRoles());
        return $token;
    }

    public function testIfContainerExists()
    {
        $this->assertNotNull($this->client);
        $this->assertNotNull($this->container);
    }
}
