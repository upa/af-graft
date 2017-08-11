
/* af_skip.c
 *
 * skip over socket processing
 *
 * Address family implementation of the skip based on a thin socket
 * layer connecting a socket opened at a (container) netns and a
 * socket opened at the host network stack (default netns).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include <skip.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt



/* Per netnamespace parameters.
 * af_skip keeps endpoint tables for per netnamespace
 */
static unsigned int skip_net_id;

struct skip_net {
	struct net 		*net;		/* this netnamespace */
	struct list_head	ep_list;	/* struct skip_endpoint */
};

struct skip_endpoint {
	struct list_head	list;
	struct rcu_head		rcu;

	char epname[AF_SKIP_EPNAME_MAX];
	struct sockaddr_storage saddr;	/* actual endpoint in the host */
};


static struct skip_endpoint *skip_find_ep(struct skip_net *skip, char *epname)
{
	struct skip_endpoint *ep;

	list_for_each_entry_rcu(ep, &skip->ep_list, list) {
		if (strncmp(ep->epname, epname, AF_SKIP_EPNAME_MAX) == 0)
			return ep;
	}

	return NULL;
}

static int skip_add_ep(struct skip_net *skip,
			char *epname, struct sockaddr_storage saddr)
{
	bool found = false;
	struct skip_endpoint *ep, *next;

	ep = (struct skip_endpoint *)kmalloc(sizeof(struct skip_endpoint),
					     GFP_KERNEL);
	if (!ep)
		return -ENOMEM;
	memset(ep, 0, sizeof(*ep));

	strncpy(ep->epname, epname, AF_SKIP_EPNAME_MAX);
	ep->saddr = saddr;


	/* not needed, but i want to sort. */
	list_for_each_entry_rcu(next, &skip->ep_list, list) {
		if (strncmp(ep->epname, next->epname,
			    AF_SKIP_EPNAME_MAX) < 0) {
			found = true;
			break;
		}
	}
	if (found)
		__list_add_rcu(&ep->list, next->list.prev, &next->list);
	else
		list_add_tail_rcu(&ep->list, &skip->ep_list);

	return 0;
}

static void skip_del_ep(struct skip_endpoint *ep)
{
	list_del_rcu(&ep->list);
	kfree_rcu(ep, rcu);
}


static __net_init int skip_init_net(struct net *net)
{
	struct skip_net *skip = net_generic(net, skip_net_id);

	skip->net = net;
	INIT_LIST_HEAD(&skip->ep_list);
	
	return 0;
}

static __net_exit void skip_exit_net(struct net *net)
{
	struct skip_net *skip = net_generic(net, skip_net_id);
	struct skip_endpoint *ep, *next;

	rcu_read_lock();
	list_for_each_entry_safe(ep, next, &skip->ep_list, list) {
		skip_del_ep(ep);
	}
	rcu_read_unlock();

	return;
}

static struct pernet_operations skip_net_ops = {
	.init	= skip_init_net,
	.exit	= skip_exit_net,
	.id	= &skip_net_id,
	.size	= sizeof(struct skip_net),
};




/* Generic Netlink implementation */

static int skip_nl_add_ep(struct sk_buff *skb, struct genl_info * info);
static int skip_nl_del_ep(struct sk_buff *skb, struct genl_info * info);
static int skip_nl_dump_ep(struct sk_buff *skb, struct netlink_callback *cb);

static struct nla_policy skip_nl_policy[AF_SKIP_ATTR_MAX + 1] = {
	[AF_SKIP_ATTR_ENDPOINT]	= { .type = NLA_BINARY,
				    .len = sizeof(struct af_skip_endpoint) },
};

static struct genl_ops skip_nl_ops[] = {
	{
		.cmd	= AF_SKIP_CMD_ADD_ENDPOINT,
		.doit	= skip_nl_add_ep,
		.policy	= skip_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= AF_SKIP_CMD_DEL_ENDPOINT,
		.doit	= skip_nl_del_ep,
		.policy	= skip_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= AF_SKIP_CMD_GET_ENDPOINT,
		.dumpit	= skip_nl_dump_ep,
		.policy	= skip_nl_policy,
	},
};

static struct genl_family skip_nl_family = {
	.name		= AF_SKIP_GENL_NAME,
	.version	= AF_SKIP_GENL_VERSION,
	.maxattr	= AF_SKIP_ATTR_MAX,
	.hdrsize	= 0,
	.ops		= skip_nl_ops,
	.n_ops		= ARRAY_SIZE(skip_nl_ops),
	.module		= THIS_MODULE,
};


static int skip_nl_add_ep(struct sk_buff *skb, struct genl_info *info)
{
	int ret;
	struct net *net = sock_net(skb->sk);
	struct skip_net *skip = net_generic(net, skip_net_id);
	struct skip_endpoint *ep;
	struct af_skip_endpoint skip_ep;

	if (!info->attrs[AF_SKIP_ATTR_ENDPOINT])
		return -EINVAL;

	nla_memcpy(&skip_ep, info->attrs[AF_SKIP_ATTR_ENDPOINT],
		   sizeof(skip_ep));

	if (skip_ep.ssk_epname[0] == '\0') {
		/* never allow NULL name endpoint. */
		return -EINVAL;
	}

	ep = skip_find_ep(skip, skip_ep.ssk_epname);
	if (ep)
		return -EEXIST;

	ret = skip_add_ep(skip, skip_ep.ssk_epname, skip_ep.ssk_saddr);
	if (ret < 0)
		return ret;

	return 0;
}

static int skip_nl_del_ep(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct skip_net *skip = net_generic(net, skip_net_id);
	struct skip_endpoint *ep;
	struct af_skip_endpoint skip_ep;

	if (!info->attrs[AF_SKIP_ATTR_ENDPOINT])
		return -EINVAL;

	nla_memcpy(&skip_ep, info->attrs[AF_SKIP_ATTR_ENDPOINT],
		   sizeof(skip_ep));

	ep = skip_find_ep(skip, skip_ep.ssk_epname);
	if (!ep)
		return -ENOENT;

	skip_del_ep(ep);

	return 0;
}

static int skip_nl_send_ep(struct sk_buff *skb, u32 portid, u32 seq,
			   int flags, struct skip_endpoint *ep)
{
	void *hdr;
	struct af_skip_endpoint skip_ep;

	hdr = genlmsg_put(skb, portid, seq, &skip_nl_family, flags,
			  AF_SKIP_CMD_GET_ENDPOINT);

	if (!hdr)
		return -EMSGSIZE;

	strncpy(skip_ep.ssk_epname, ep->epname, AF_SKIP_EPNAME_MAX);
	skip_ep.ssk_saddr = ep->saddr;

	if (nla_put(skb, AF_SKIP_ATTR_ENDPOINT, sizeof(skip_ep), &skip_ep))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int skip_nl_dump_ep(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ret, idx, cnt;
	struct skip_net *skip = net_generic(sock_net(skb->sk), skip_net_id);
	struct skip_endpoint *ep;

	cnt = 0;
	idx = cb->args[0];
	
	list_for_each_entry_rcu(ep, &skip->ep_list, list) {
		if (idx > cnt) {
			cnt ++;
			continue;
		}

		ret = skip_nl_send_ep(skb, NETLINK_CB(cb->skb).portid,
				      cb->nlh->nlmsg_seq, NLM_F_MULTI, ep);
		if (ret < 0)
			return ret;

		break;
	}

	cb->args[0] = cnt + 1;

	return skb->len;
}




/* AF_SKIP socket implementation  */

struct skip_sock {
	struct sock sk;

	int type;
	int protocol;
	int kern;

	struct sockaddr_skip saddr_sk;	/* the name of this skip socket */
	struct sockaddr_storage ep;	/* actual endpoint in the host */

	struct socket *sock;	/* this socket */
	struct socket *hsock;	/* socket with original family at host */
};

static inline struct skip_sock *skip_sk(const struct sock *sk)
{
	return (struct skip_sock *)sk;
}

static inline struct socket *skip_hsock(struct skip_sock *ssk)
{
	return ssk->hsock;
}


static int skip_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct skip_sock *ssk;

	if (!sk) {
		pr_debug("%s, NULL sk\n", __func__);
		return 0;
	}
	pr_debug("%s\n", __func__);

	ssk = skip_sk(sk);
	if (ssk->hsock)
		sock_release(ssk->hsock);
	sock_orphan(sk);
	sk_refcnt_debug_release(sk);
	sock_put(sk);

	sock->sk = NULL;

	return 0;
}

static int skip_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	int ret;
	struct skip_sock *ssk = skip_sk(sock->sk);
	struct skip_net *skip = net_generic(sock_net(sock->sk), skip_net_id);
	struct skip_endpoint *ep;
	struct sockaddr_skip *saddr_sk = (struct sockaddr_skip *)uaddr;

	/*
	 * 1. find endpoint according to the uaddr (sockaddr_skip)
	 * 2. if found, create a socket on host stack with
	 * the address family of the endpoint, type and protocol of
	 * this socket.
	 * 3. call bind() for the host socket with endpoint
	 */

	/* 1. find skip endpoint specified by uaddr */
	if (addr_len < sizeof(struct sockaddr_skip))
		return -EINVAL;

	if (saddr_sk->ssk_family != AF_SKIP)
		return -EAFNOSUPPORT;

	ep = skip_find_ep(skip, saddr_sk->ssk_epname);
	if (!ep)
		return -ENOENT;

	memcpy(&ssk->saddr_sk, uaddr, addr_len); /* save for getname */


	/* 2. create a host socket */
	ret = __sock_create(get_net(&init_net), ep->saddr.ss_family,
			    ssk->type, ssk->protocol, &ssk->hsock, ssk->kern);
	if (ret < 0)  {
		pr_err("%s: failed to create a socket on default netns\n",
		       __func__);
		ssk->hsock = NULL;
		return ret;
	}


	/* 3. bind() the host socket into the endpoint */
	ret = ssk->hsock->ops->bind(ssk->hsock,
				    (struct sockaddr *)&ep->saddr,
				    sizeof(ep->saddr));
	if (ret) {
		pr_debug("%s: hsock->ops->bind() faied, ret=%d\n",
			 __func__, ret);
		return ret;
	}

	return 0;
}

static int skip_connect(struct socket *sock, struct sockaddr *vaddr,
			int sockaddr_len, int flags)
{
	struct socket *hsock = skip_hsock(skip_sk(sock->sk));

	/* XXX: should i accept AF_SKIP endpoints for destinations? */

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->connect(hsock, vaddr, sockaddr_len, flags);
}

static int skip_socketpair(struct socket *sock1, struct socket *sock2)
{
	/* XXX: ??? */

	struct socket *hsock = skip_hsock(skip_sk(sock1->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->socketpair(hsock, sock2);
}

static int skip_accept(struct socket *sock, struct socket *newsocket,
		       int flags)
{
	struct socket *hsock = skip_hsock(skip_sk(sock->sk));	

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	/* cut the newsocket from skip to the module of hsock.
	 * accept() increments the refcnt of the module of newsocket
	 * that is af_skip.ko, THIS_MODULE.
	 */
	newsocket->ops = hsock->ops;
	__module_get(newsocket->ops->owner);
	module_put(THIS_MODULE);

	return hsock->ops->accept(hsock, newsocket, flags);
}

static int skip_getname(struct socket *sock, struct sockaddr *addr,
			int *sockaddr_len, int peer)
{
	struct skip_sock *ssk = skip_sk(sock->sk);
	struct socket *hsock = skip_hsock(ssk);

	if (peer) {
		/* skip socket (currently) does not have any peer.
		 * connection semantics are handled by host sockets.
		 */
		if (hsock)
			return hsock->ops->getname(hsock, addr,
						   sockaddr_len, peer);
		else {
			pr_debug("%s: host socket is not created\n", __func__);
			return -EADDRNOTAVAIL;
		}
	} else {
		/* getsockname() for this socket.
		 * this (currently) returns sockaddr_skip.
		 */
		memcpy(addr, &ssk->saddr_sk, sizeof(ssk->saddr_sk));
		*sockaddr_len = sizeof(ssk->saddr_sk);
		return 0;
	}

	return 0;
}

static unsigned int skip_poll(struct file *file, struct socket *sock,
			      struct poll_table_struct *wait)
{
	struct socket *hsock;

	hsock = skip_hsock(skip_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->poll(file, hsock, wait);
}


static int skip_ioctl(struct socket *sock, unsigned int cmd,
		      unsigned long arg)
{
	struct socket *hsock = skip_hsock(skip_sk(sock->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->ioctl(hsock, cmd, arg);
}

static int skip_listen(struct socket *sock, int len)
{
	struct socket *hsock = skip_hsock(skip_sk(sock->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->listen(hsock, len);
}


static int skip_shutdown(struct socket *sock, int flags)
{
	struct socket *hsock = skip_hsock(skip_sk(sock->sk));

	/* XXX:
	 * shutdown() is called for socket accept()ed.
	 * accept() sockets do not have virtual socket on netns.
	 * Thus, in this function, only hsock->ops->shutdown is called.
	 */

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->shutdown(hsock, flags);
}

static int skip_setsockopt(struct socket *sock, int level,
			   int optname, char __user *optval,
			   unsigned int optlen)
{
	struct socket *hsock = skip_hsock(skip_sk(sock->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->setsockopt(hsock, level, optname, optval, optlen);
}

static int skip_getsockopt(struct socket *sock, int level,
			   int optname, char __user *optval,
			   int __user * optlen)
{
	struct socket *hsock = skip_hsock(skip_sk(sock->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->getsockopt(hsock, level, optname, optval, optlen);
}

static int skip_sendmsg(struct socket *sock,
			struct msghdr *m, size_t total_len)
{
	struct socket *hsock;

	hsock = skip_hsock(skip_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->sendmsg(hsock, m, total_len);
}

static int skip_recvmsg(struct socket *sock,
			struct msghdr *m, size_t total_len, int flags)
{
	struct socket *hsock;

	hsock = skip_hsock(skip_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->recvmsg(hsock, m, total_len, flags);
}

static ssize_t skip_sendpage(struct socket *sock, struct page *page,
			     int offset, size_t size, int flags)
{
	struct socket *hsock;

	hsock = skip_hsock(skip_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->sendpage(hsock, page, offset, size, flags);
}


static ssize_t skip_splice_read(struct socket *sock, loff_t *ppos,
			       struct pipe_inode_info *pipe,
			       size_t len, unsigned int flags)
{
	struct socket *hsock;

	hsock = skip_hsock(skip_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->splice_read(hsock, ppos, pipe, len, flags);
}

static int skip_set_peek_off(struct sock *sk, int val)
{
	struct socket *hsock = skip_hsock(skip_sk(sk));
	
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->set_peek_off(hsock->sk, val);
}

static const struct proto_ops skip_proto_ops = {
	.family		= PF_SKIP,
	.owner		= THIS_MODULE,
	.release	= skip_release,
	.bind		= skip_bind,
	.connect	= skip_connect,
	.socketpair	= skip_socketpair,
	.accept		= skip_accept,
	.getname	= skip_getname,
	.poll		= skip_poll,
	.ioctl		= skip_ioctl,
	.listen		= skip_listen,
	.shutdown	= skip_shutdown,
	.setsockopt	= skip_setsockopt,
	.getsockopt	= skip_getsockopt,
	.sendmsg	= skip_sendmsg,
	.recvmsg	= skip_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= skip_sendpage,
	.splice_read	= skip_splice_read,
	.set_peek_off	= skip_set_peek_off,
};

static struct proto skip_proto = {
	.name		= "SKIP",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct skip_sock),
};

static int skip_create(struct net *net, struct socket *sock,
		       int protocol, int kern)
{
	struct sock *sk;
	struct skip_sock *ssk;

	pr_debug("%s\n", __func__);

	sock->ops = &skip_proto_ops;

	sk = sk_alloc(net, PF_SKIP, GFP_KERNEL, &skip_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	ssk = skip_sk(sk);
	ssk->sock = sock;
	ssk->hsock = NULL;
	ssk->saddr_sk.ssk_family = AF_INET;

	/* NOTE:
	 * When skip socket is created, the address family used to open
	 * a socket in host stack is not decided. It is decided when
	 * bind() is called for this skip socket and an endpoint is found.
	 * Thus, actual host socket (ssk->hsock) is created in skip_bind().
	 */
	ssk->type = sk->sk_type;
	ssk->protocol = sk->sk_protocol;
	ssk->kern = kern;

	return 0;
}


static struct net_proto_family skip_family_ops = {
	.family	= PF_SKIP,
	.create	= skip_create,
	.owner	= THIS_MODULE,
};


static int __init af_skip_init(void)
{
	int ret;

	ret = register_pernet_subsys(&skip_net_ops);
	if (ret)
		goto netns_failed;

	ret = genl_register_family(&skip_nl_family);
	if (ret)
		goto genl_failed;

	ret = proto_register(&skip_proto, 1);
	if (ret) {
		pr_err("%s: proto_register failed '%d'\n", __func__, ret);
		goto proto_register_failed;
	}

	ret = sock_register(&skip_family_ops);
	if (ret) {
		pr_err("%s: sock_register failed '%d'\n", __func__, ret);
		goto sock_register_failed;
	}

	pr_info("skip version (%s) is loaded\n", SKIP_VERSION);

	return ret;

sock_register_failed:
	proto_unregister(&skip_proto);
proto_register_failed:
	genl_unregister_family(&skip_nl_family);
genl_failed:
	unregister_pernet_subsys(&skip_net_ops);
netns_failed:
	return ret;
}


static void __exit af_skip_exit(void)
{
	sock_unregister(PF_SKIP);
	proto_unregister(&skip_proto);
	genl_unregister_family(&skip_nl_family);
	unregister_pernet_subsys(&skip_net_ops);

	pr_info("skip version (%s) is unloaded\n", SKIP_VERSION);
}


module_init(af_skip_init);
module_exit(af_skip_exit);
MODULE_AUTHOR("Ryo Nakamura <upa@haeena.net>");
MODULE_LICENSE("GPL");
MODULE_VERSION(SKIP_VERSION);
