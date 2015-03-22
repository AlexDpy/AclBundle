<?php

namespace AlexDpy\AclBundle\AclManager\Tests\Manager;

use AlexDpy\AclBundle\Tests\Model\PostObject;
use AlexDpy\AclBundle\Tests\Security\AbstractSecurityTest;
use Doctrine\DBAL\Query\QueryBuilder as DBALQueryBuilder;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Types\Type;
use Doctrine\ORM\Query;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\User\UserInterface;

class AclFilterTest extends AbstractSecurityTest
{
    /**
     * @var PostObject[]
     */
    protected $posts = [];

    public function setUp()
    {
        parent::setUp();

        $schema = new Schema();
        $posts = $schema->createTable('posts');
        $posts->addColumn('id', Type::INTEGER);
        $posts->setPrimaryKey(['id']);

        $this->connection->exec("DROP TABLE IF EXISTS posts");
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->exec($sql);
        }

        $i = 1;
        while ($i <= 10) {
            $this->connection->insert('posts', ['id' => $i]);
            $this->posts[$i] = new PostObject($i);
            $i++;
        }
    }

    protected function tearDown()
    {
        parent::tearDown();
        $this->connection->exec("DROP TABLE IF EXISTS posts");
    }


    public function testFilter()
    {
        $alice = $this->generateUser('alice', ['ROLE_H_ADMIN']);
        $bob = $this->generateUser('bob', ['ROLE_H_SUPER_ADMIN']);
        $mallory = $this->generateUser('mallory', ['ROLE_H_USER']);
        $this->authenticateUser($alice);

        $this->aclManager->grantRoleOnObject('view', $this->posts[1], 'ROLE_H_USER');
        $this->aclManager->grantRoleOnObject('view', $this->posts[2], 'ROLE_H_ADMIN');
        $this->aclManager->grantRoleOnObject('view', $this->posts[3], 'ROLE_H_SUPER_ADMIN');
        $this->aclManager->grantUserOnObject('view', $this->posts[4], $alice);
        $this->aclManager->grantUserOnObject('edit', $this->posts[5], $alice);
        $this->aclManager->grantUserOnObject('create', $this->posts[6], $alice);

        $this->verify([1, 2, 4, 5], 'view');
        $this->verify([1, 2, 3], 'view', $bob);
        $this->verify([1], 'view', $mallory);
    }

    /**
     * @param int[]         $expected
     * @param string        $permission
     * @param UserInterface $user
     */
    private function verify(array $expected, $permission, UserInterface $user = null)
    {
        $DBALQueryBuilder = new DBALQueryBuilder($this->connection);
        $DBALQueryBuilder->select('p.id')->from('posts', 'p');
        $this->aclFilter->apply($DBALQueryBuilder, $permission, 'AlexDpy\AclBundle\Tests\Model\PostObject', 'p.id', $user);
        $this->assertEquals(
            $expected,
            $this->getPostIds($DBALQueryBuilder),
            'AclFilter did not math using DBALQueryBuilder'
        );

        $ORMQueryBuilder = $this->em->createQueryBuilder();
        $ORMQueryBuilder->select('p')->from('AlexDpy\AclBundle\Tests\Model\PostObject', 'p');
        $query = $this->aclFilter->apply($ORMQueryBuilder, 'view', 'AlexDpy\AclBundle\Tests\Model\PostObject', 'p.id', $user);
        $this->assertEquals(
            $expected,
            $this->getPostIds($query),
            'AclFilter did not math using ORMQueryBuilder'
        );
    }

    /**
     * @param DBALQueryBuilder|Query $queryBuilder
     * @return int[]
     */
    private function getPostIds($queryBuilder)
    {
        $ids = [];

        if ($queryBuilder instanceof DBALQueryBuilder) {
            foreach ($queryBuilder->execute()->fetchAll() as $post) {
                $ids[] = (int) $post['id'];
            }
        } elseif ($queryBuilder instanceof Query) {
            foreach ($queryBuilder->getResult() as $post) {
                $ids[] = $post->getId();
            }
        }

        return $ids;
    }
}
