
/* af_graft.c
 *
 * Grafingt sockets accross netnamespace.
 *
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

#include <graft.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


/* Per netnamespace parameters.
 * af_graft keeps endpoint tables for per netnamespace
 */
static unsigned int graft_net_id;

struct graft_net {
	struct net 		*net;		/* this netnamespace */
	struct list_head	ep_list;	/* struct graft_endpoint */
};

struct graft_endpoint {
	struct list_head	list;
	struct rcu_head		rcu;

	char			epname[AF_GRAFT_EPNAME_MAX];
	int			addrlen;	/* length of actual saddr */
	struct sockaddr_storage saddr;	/* actual endpoint in the host */
};


static struct graft_endpoint *graft_find_ep(struct graft_net *graft,
					    char *epname)
{
	struct graft_endpoint *ep;

	list_for_each_entry_rcu(ep, &graft->ep_list, list) {
		if (strncmp(ep->epname, epname, AF_GRAFT_EPNAME_MAX) == 0)
			return ep;
	}

	return NULL;
}

static int graft_add_ep(struct graft_net *graft, char *epname,
			struct sockaddr_storage saddr, int addrlen)

{
	bool found = false;
	struct graft_endpoint *ep, *next;

	ep = (struct graft_endpoint *)kmalloc(sizeof(struct graft_endpoint),
					      GFP_KERNEL);
	if (!ep)
		return -ENOMEM;
	memset(ep, 0, sizeof(*ep));

	strncpy(ep->epname, epname, AF_GRAFT_EPNAME_MAX);
	ep->addrlen = addrlen;
	ep->saddr = saddr;

	/* not needed, but i want to sort. */
	list_for_each_entry_rcu(next, &graft->ep_list, list) {
		if (strncmp(ep->epname, next->epname,
			    AF_GRAFT_EPNAME_MAX) < 0) {
			found = true;
			break;
		}
	}
	if (found)
		__list_add_rcu(&ep->list, next->list.prev, &next->list);
	else
		list_add_tail_rcu(&ep->list, &graft->ep_list);

	return 0;
}

static void graft_del_ep(struct graft_endpoint *ep)
{
	list_del_rcu(&ep->list);
	kfree_rcu(ep, rcu);
}


static __net_init int graft_init_net(struct net *net)
{
	struct graft_net *graft = net_generic(net, graft_net_id);

	graft->net = net;
	INIT_LIST_HEAD(&graft->ep_list);
	
	return 0;
}

static __net_exit void graft_exit_net(struct net *net)
{
	struct graft_net *graft = net_generic(net, graft_net_id);
	struct graft_endpoint *ep, *next;

	rcu_read_lock();
	list_for_each_entry_safe(ep, next, &graft->ep_list, list) {
		graft_del_ep(ep);
	}
	rcu_read_unlock();

	return;
}

static struct pernet_operations graft_net_ops = {
	.init	= graft_init_net,
	.exit	= graft_exit_net,
	.id	= &graft_net_id,
	.size	= sizeof(struct graft_net),
};




/* Generic Netlink implementation */

static int graft_nl_add_ep(struct sk_buff *skb, struct genl_info * info);
static int graft_nl_del_ep(struct sk_buff *skb, struct genl_info * info);
static int graft_nl_dump_ep(struct sk_buff *skb, struct netlink_callback *cb);

static struct nla_policy graft_nl_policy[AF_GRAFT_ATTR_MAX + 1] = {
	[AF_GRAFT_ATTR_ENDPOINT] = { .type = NLA_BINARY,
				     .len =
				     sizeof(struct graft_genl_endpoint) },
};

static struct genl_ops graft_nl_ops[] = {
	{
		.cmd	= AF_GRAFT_CMD_ADD_ENDPOINT,
		.doit	= graft_nl_add_ep,
		.policy	= graft_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= AF_GRAFT_CMD_DEL_ENDPOINT,
		.doit	= graft_nl_del_ep,
		.policy	= graft_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= AF_GRAFT_CMD_GET_ENDPOINT,
		.dumpit	= graft_nl_dump_ep,
		.policy	= graft_nl_policy,
	},
};

static struct genl_family graft_nl_family = {
	.name		= AF_GRAFT_GENL_NAME,
	.version	= AF_GRAFT_GENL_VERSION,
	.maxattr	= AF_GRAFT_ATTR_MAX,
	.hdrsize	= 0,
	.netnsok	= true,
	.ops		= graft_nl_ops,
	.n_ops		= ARRAY_SIZE(graft_nl_ops),
	.module		= THIS_MODULE,
};


static int graft_nl_add_ep(struct sk_buff *skb, struct genl_info *info)
{
	int ret;
	struct net *net = sock_net(skb->sk);
	struct graft_net *graft = net_generic(net, graft_net_id);
	struct graft_endpoint *ep;
	struct graft_genl_endpoint graft_ep;

	if (!info->attrs[AF_GRAFT_ATTR_ENDPOINT])
		return -EINVAL;

	nla_memcpy(&graft_ep, info->attrs[AF_GRAFT_ATTR_ENDPOINT],
		   sizeof(graft_ep));

	if (graft_ep.epname[0] == '\0') {
		/* never allow NULL name endpoint. */
		return -EINVAL;
	}

	ep = graft_find_ep(graft, graft_ep.epname);
	if (ep)
		return -EEXIST;

	ret = graft_add_ep(graft, graft_ep.epname,
			   graft_ep.saddr, graft_ep.addrlen);
	if (ret < 0)
		return ret;

	return 0;
}

static int graft_nl_del_ep(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct graft_net *graft = net_generic(net, graft_net_id);
	struct graft_endpoint *ep;
	struct graft_genl_endpoint graft_ep;

	if (!info->attrs[AF_GRAFT_ATTR_ENDPOINT])
		return -EINVAL;

	nla_memcpy(&graft_ep, info->attrs[AF_GRAFT_ATTR_ENDPOINT],
		   sizeof(graft_ep));

	ep = graft_find_ep(graft, graft_ep.epname);
	if (!ep)
		return -ENOENT;

	graft_del_ep(ep);

	return 0;
}

static int graft_nl_send_ep(struct sk_buff *skb, u32 portid, u32 seq,
			    int flags, struct graft_endpoint *ep)
{
	void *hdr;
	struct graft_genl_endpoint graft_ep;

	hdr = genlmsg_put(skb, portid, seq, &graft_nl_family, flags,
			  AF_GRAFT_CMD_GET_ENDPOINT);

	if (!hdr)
		return -EMSGSIZE;

	strncpy(graft_ep.epname, ep->epname, AF_GRAFT_EPNAME_MAX);
	graft_ep.saddr = ep->saddr;

	if (nla_put(skb, AF_GRAFT_ATTR_ENDPOINT, sizeof(graft_ep), &graft_ep))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int graft_nl_dump_ep(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ret, idx, cnt;
	struct graft_net *graft = net_generic(sock_net(skb->sk), graft_net_id);
	struct graft_endpoint *ep;

	cnt = 0;
	idx = cb->args[0];
	
	list_for_each_entry_rcu(ep, &graft->ep_list, list) {
		if (idx > cnt) {
			cnt ++;
			continue;
		}

		ret = graft_nl_send_ep(skb, NETLINK_CB(cb->skb).portid,
				       cb->nlh->nlmsg_seq, NLM_F_MULTI, ep);
		if (ret < 0)
			return ret;

		break;
	}

	cb->args[0] = cnt + 1;

	return skb->len;
}




/* AF_GRAFT socket implementation  */

/* delayed setsockopt() structure */
struct graft_sso {
	char *optval;
	unsigned int optlen;
	struct graft_sso_result res;
};
#define GRAFT_SSO_MAX	64

struct graft_sock {
	struct sock sk;

	int type;
	int protocol;
	int kern;

	struct sockaddr_gr saddr_gr;	/* the name of this graft socket */
	struct sockaddr_storage ep;	/* actual endpoint in the host */

	struct socket *sock;	/* this socket */
	struct socket *hsock;	/* socket with original family at host */

	/* setsockopt() related */
	spinlock_t sso_lock;
	int graft_so_delayed;
	struct graft_sso *sso[GRAFT_SSO_MAX];
};


static inline struct graft_sock *graft_sk(const struct sock *sk)
{
	return (struct graft_sock *)sk;
}

static inline struct socket *graft_hsock(struct graft_sock *gsk)
{
	return gsk->hsock;
}



/* setsockopt related functions */

static void graft_sso_free(struct graft_sso *sso) {
	kfree(sso->optval);
	kfree(sso);
}

static int wrap_setsockopt(struct socket *sock,
			   int level, int optname, char __user *optval,
			   unsigned int optlen)
{
	if (!sock) {
		pr_debug("%s: maybe host socket is not created\n",
			 __func__);
		return -EADDRNOTAVAIL;
	}

	return kernel_setsockopt(sock, level, optname, optval, optlen);
}

static int graft_sso_delayed_enqueue(struct graft_sock *gsk,
				     int level, int optname,
				     char __user *optval, unsigned int optlen)
{
	/* call under spin_lock_bh(&gsk->sso_lock); */

	int n;
	struct graft_sso *sso;

	pr_debug("%s: level=%d, opt=%d\n", __func__, level, optname);

	sso = (struct graft_sso *)kmalloc(sizeof(*sso), GFP_KERNEL);
	if (!sso)
		return -ENOMEM;
	if (!sso->optval) {
		kfree(sso);
		return -ENOMEM;
	}

	sso->res.ret = 0;
	sso->res.level = level;
	sso->res.optname = optname;
	sso->optlen = optlen;
	if (sso->optval) {
		sso->optval = kmalloc(optlen, GFP_KERNEL);
		copy_from_user(sso->optval, optval, optlen);
	} else {
		sso->optval = NULL;
	}

	for (n = 0; n < GRAFT_SSO_MAX; n++) {
		if (!gsk->sso[n]) {
			gsk->sso[n] = sso;
			break;
		}
	}
	if (n >= GRAFT_SSO_MAX) {
		pr_debug("%s: no delayed setsockopt slot!\n", __func__);
		graft_sso_free(sso);
		return -ENOBUFS;
	}

	return 0;
}

static int graft_sso_delayed_execute(struct graft_sock *gsk)
{
	/* call under spin_lock_bh(&gsk->sso_lock); */

	int n, ret;
	struct graft_sso *sso;
	struct socket *hsock = graft_hsock(gsk);

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	for (n = 0; n < GRAFT_SSO_MAX; n++) {
		sso = gsk->sso[n];
		if (!sso)
			continue;

		ret = wrap_setsockopt(hsock, sso->res.level,
				      sso->res.optname,
				      sso->optval, sso->optlen);
		sso->res.ret = ret;

		pr_debug("%s: level=%d, opt=%d, val=%d len=%u, ret=%d\n",
			 __func__,
			 sso->res.level, sso->res.optname,
			 *((int *)sso->optval), sso->optlen, ret);
	}

	return 0;
}

static int graft_sso_delayed_result(struct graft_sock *gsk,
				    char __user *optval, int __user *optlen)
{
	int ret = 0, res_siz, n, len, totlen;
	char __user *ptr;
	struct graft_sso *sso;

	res_siz = sizeof(struct graft_sso_result);
	get_user(len, optlen);
	totlen = 0;
	ptr = optval;

	for (n = 0; n < GRAFT_SSO_MAX; n++) {
		sso = gsk->sso[n];
		if (!sso)
			continue;

		if (len - res_siz < 0) {
			ret = -ENOBUFS;
			break;
		}

		copy_to_user(ptr, &sso->res, res_siz);
		totlen += res_siz;
		ptr += res_siz;
		len -= res_siz;
		kfree(sso->optval);
		kfree(sso);
		gsk->sso[n] = NULL;
	}

	put_user(totlen, optlen);

	return ret;
}


/* Graft socket operations */
static int graft_release(struct socket *sock)
{
	int n;
	struct sock *sk = sock->sk;
	struct graft_sock *gsk;

	if (!sk) {
		pr_debug("%s, NULL sk\n", __func__);
		return 0;
	}
	pr_debug("%s\n", __func__);

	gsk = graft_sk(sk);
	if (gsk->hsock)
		sock_release(gsk->hsock);

	spin_lock_bh(&gsk->sso_lock);
	for (n = 0; n < GRAFT_SSO_MAX; n++) {
		if (gsk->sso[n]) {
			graft_sso_free(gsk->sso[n]);
			gsk->sso[n] = NULL;
		}
	}
	spin_unlock_bh(&gsk->sso_lock);

	sock_orphan(sk);
	sk_refcnt_debug_release(sk);
	sock_put(sk);

	sock->sk = NULL;

	return 0;
}

static int graft_bind(struct socket *sock, struct sockaddr *uaddr, int addrlen)
{
	int ret;
	struct net *net = sock_net(sock->sk);
	struct graft_sock *gsk = graft_sk(sock->sk);
	struct graft_net *graft = net_generic(net, graft_net_id);
	struct graft_endpoint *ep;
	struct sockaddr_gr *saddr_gr = (struct sockaddr_gr *)uaddr;

	/*
	 * 1. find endpoint according to the uaddr (sockaddr_gr)
	 * 2. if found, create a socket on host stack with
	 * the address family of the endpoint, type and protocol of
	 * this socket.
	 * 3. if delayed setsockopt()s exist, execute them.
	 * 4. call bind() for the host socket with endpoint
	 */

	/* 1. find graft endpoint specified by uaddr */
	if (addrlen < sizeof(struct sockaddr_gr))
		return -EINVAL;

	if (saddr_gr->sgr_family != AF_GRAFT)
		return -EAFNOSUPPORT;

	ep = graft_find_ep(graft, saddr_gr->sgr_epname);
	if (!ep)
		return -ENOENT;

	memcpy(&gsk->saddr_gr, uaddr, addrlen); /* save for getname */


	/* 2. create a host socket */
	ret = __sock_create(get_net(&init_net), ep->saddr.ss_family,
			    gsk->type, gsk->protocol, &gsk->hsock, gsk->kern);
	if (ret < 0)  {
		pr_err("%s: failed to create a socket on default netns\n",
		       __func__);
		gsk->hsock = NULL;
		return ret;
	}


	/* 3. execute delayed setsockopt() */
	spin_lock_bh(&gsk->sso_lock);
	graft_sso_delayed_execute(gsk);
	spin_unlock_bh(&gsk->sso_lock);


	/* 4. bind() the host socket into the endpoint */
	ret = gsk->hsock->ops->bind(gsk->hsock,
				    (struct sockaddr *)&ep->saddr,
				    ep->addrlen);
	if (ret) {
		pr_debug("%s: hsock->ops->bind() faied, ret=%d\n",
			 __func__, ret);
		return ret;
	}

	return 0;
}

static int graft_connect(struct socket *sock, struct sockaddr *vaddr,
			 int sockaddr_len, int flags)
{
	struct socket *hsock = graft_hsock(graft_sk(sock->sk));

	/* XXX: should i accept AF_GRAFT endpoints for destinations? */

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->connect(hsock, vaddr, sockaddr_len, flags);
}

static int graft_socketpair(struct socket *sock1, struct socket *sock2)
{
	/* XXX: ??? */

	struct socket *hsock = graft_hsock(graft_sk(sock1->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->socketpair(hsock, sock2);
}

static int graft_accept(struct socket *sock, struct socket *newsocket,
			int flags)
{
	struct socket *hsock = graft_hsock(graft_sk(sock->sk));	

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	/* cut the newsocket from graft to the module of hsock.
	 * accept() increments the refcnt of the module of newsocket
	 * that is af_graft.ko, THIS_MODULE.
	 */
	newsocket->ops = hsock->ops;
	__module_get(newsocket->ops->owner);
	module_put(THIS_MODULE);

	return hsock->ops->accept(hsock, newsocket, flags);
}

static int graft_getname(struct socket *sock, struct sockaddr *addr,
			 int *sockaddr_len, int peer)
{
	struct graft_sock *gsk = graft_sk(sock->sk);
	struct socket *hsock = graft_hsock(gsk);

	if (peer) {
		/* graft socket (currently) does not have any peer.
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
		 * this (currently) returns sockaddr_gr.
		 */
		memcpy(addr, &gsk->saddr_gr, sizeof(gsk->saddr_gr));
		*sockaddr_len = sizeof(gsk->saddr_gr);
		return 0;
	}

	return 0;
}

static unsigned int graft_poll(struct file *file, struct socket *sock,
			       struct poll_table_struct *wait)
{
	struct socket *hsock;

	hsock = graft_hsock(graft_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->poll(file, hsock, wait);
}


static int graft_ioctl(struct socket *sock, unsigned int cmd,
		       unsigned long arg)
{
	struct socket *hsock = graft_hsock(graft_sk(sock->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->ioctl(hsock, cmd, arg);
}

static int graft_listen(struct socket *sock, int len)
{
	struct socket *hsock = graft_hsock(graft_sk(sock->sk));

	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->listen(hsock, len);
}


static int graft_shutdown(struct socket *sock, int flags)
{
	struct socket *hsock = graft_hsock(graft_sk(sock->sk));

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

static int graft_setsockopt(struct socket *sock, int level,
			    int optname, char __user *optval,
			    unsigned int optlen)
{
	int val, ret = 0;
	char buf[GRAFT_SSO_TRANS_SIZE];
	struct graft_sock *gsk = graft_sk(sock->sk);
	struct graft_sso_trans *t = (struct graft_sso_trans *)buf;


	pr_debug("%s: level %d, optname %d\n", __func__, level, optname);

	spin_lock_bh(&gsk->sso_lock);

	if (level == IPPROTO_GRAFT) {
		/* setsockopt for this graft socket */
		switch (optname) {
		case GRAFT_SO_DELAYED:
			get_user(val, (int __user *)optval);
			gsk->graft_so_delayed = (val > 0) ? 1: 0;
			break;

		case GRAFT_SO_DELAYED_EXECUTE:
			ret = graft_sso_delayed_execute(gsk);
			break;

		case GRAFT_SO_TRANSPARENT:
			if (optlen < GRAFT_SSO_TRANS_SIZE) {
				ret = -EINVAL;
				goto out;
			}
			copy_from_user(t, optval, optlen);

			if (gsk->graft_so_delayed) {
				ret = graft_sso_delayed_enqueue(gsk,
								t->level,
								t->optname,
								t->optval,
								t->optlen);
			} else {
				ret = wrap_setsockopt(graft_hsock(gsk),
						      t->level,
						      t->optname,
						      t->optval,
						      t->optlen);
			}
			break;

		default:
			pr_debug("%s: invalid opt %d\n", __func__, optname);
			ret = -ENOPROTOOPT;
		}
	} else {
		/* setsockopt for the associated host socket */
		if (gsk->graft_so_delayed) {
			/* setsockopt is delayed until bind() or
			 * GRAFT_SO_DELAYED_EXECUTE is called.
			 * queueing setsockopt. */
			ret = graft_sso_delayed_enqueue(gsk, level,
							optname, optval,
							optlen);

		} else {
			/* setsockopt is not delayed. call it to host
			 * socket transparently */
			ret = wrap_setsockopt(graft_hsock(gsk),
					      t->level,
					      t->optname, t->optval,
					      t->optlen);
		}
	}

out:
	spin_unlock_bh(&gsk->sso_lock);

	return ret;
}

static int graft_getsockopt(struct socket *sock, int level,
			    int optname, char __user *optval,
			    int __user *optlen)
{
	int ret = 0;
	struct graft_sock *gsk = graft_sk(sock->sk);
	struct socket *hsock;

	pr_debug("%s: level %d, optname %d\n", __func__, level, optname);

	spin_lock_bh(&gsk->sso_lock);
	if (level == IPPROTO_GRAFT) {
		/* getsockopt for this graft socket */
		switch (optname) {
		case GRAFT_SO_DELAYED:
			put_user(sizeof(int), optlen);
			copy_to_user(optval, &gsk->graft_so_delayed,
				     sizeof(int));
			break;

		case GRAFT_SO_DELAYED_RESULT:
			ret = graft_sso_delayed_result(gsk, optval, optlen);
			break;

		default:
			pr_debug("%s: invalid opt %d\n", __func__, optname);
			ret = -ENOPROTOOPT;
		}
	} else {
		/* setsockopt for the associated host socket  */
		hsock = graft_hsock(gsk);
		if (!hsock) {
			pr_debug("%s: host socket is not created\n", __func__);
			ret = -EADDRNOTAVAIL;
		} else {
			ret = hsock->ops->getsockopt(hsock, level,
						     optname, optval, optlen);
		}
	}

	spin_lock_bh(&gsk->sso_lock);

	return ret;
}

static int graft_sendmsg(struct socket *sock,
			 struct msghdr *m, size_t total_len)
{
	struct socket *hsock;

	hsock = graft_hsock(graft_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->sendmsg(hsock, m, total_len);
}

static int graft_recvmsg(struct socket *sock,
			 struct msghdr *m, size_t total_len, int flags)
{
	struct socket *hsock;

	hsock = graft_hsock(graft_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->recvmsg(hsock, m, total_len, flags);
}

static ssize_t graft_sendpage(struct socket *sock, struct page *page,
			      int offset, size_t size, int flags)
{
	struct socket *hsock;

	hsock = graft_hsock(graft_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->sendpage(hsock, page, offset, size, flags);
}


static ssize_t graft_splice_read(struct socket *sock, loff_t *ppos,
				 struct pipe_inode_info *pipe,
				 size_t len, unsigned int flags)
{
	struct socket *hsock;

	hsock = graft_hsock(graft_sk(sock->sk));
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->splice_read(hsock, ppos, pipe, len, flags);
}

static int graft_set_peek_off(struct sock *sk, int val)
{
	struct socket *hsock = graft_hsock(graft_sk(sk));
	
	if (!hsock) {
		pr_debug("%s: host socket is not created\n", __func__);
		return -EADDRNOTAVAIL;
	}

	return hsock->ops->set_peek_off(hsock->sk, val);
}

static const struct proto_ops graft_proto_ops = {
	.family		= PF_GRAFT,
	.owner		= THIS_MODULE,
	.release	= graft_release,
	.bind		= graft_bind,
	.connect	= graft_connect,
	.socketpair	= graft_socketpair,
	.accept		= graft_accept,
	.getname	= graft_getname,
	.poll		= graft_poll,
	.ioctl		= graft_ioctl,
	.listen		= graft_listen,
	.shutdown	= graft_shutdown,
	.setsockopt	= graft_setsockopt,
	.getsockopt	= graft_getsockopt,
	.sendmsg	= graft_sendmsg,
	.recvmsg	= graft_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= graft_sendpage,
	.splice_read	= graft_splice_read,
	.set_peek_off	= graft_set_peek_off,
};

static struct proto graft_proto = {
	.name		= "GRAFT",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct graft_sock),
};

static int graft_create(struct net *net, struct socket *sock,
			int protocol, int kern)
{
	struct sock *sk;
	struct graft_sock *gsk;

	pr_debug("%s\n", __func__);

	sock->ops = &graft_proto_ops;

	sk = sk_alloc(net, PF_GRAFT, GFP_KERNEL, &graft_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	gsk = graft_sk(sk);
	gsk->sock = sock;
	gsk->hsock = NULL;
	gsk->saddr_gr.sgr_family = AF_GRAFT;

	/* NOTE:
	 * When graft socket is created, the address family used to open
	 * a socket in host stack is not decided. It is decided when
	 * bind() is called for this graft socket and an endpoint is found.
	 * Thus, actual host socket (gsk->hsock) is created in graft_bind().
	 */
	gsk->type = sk->sk_type;
	gsk->protocol = sk->sk_protocol;
	gsk->kern = kern;

	return 0;
}


static struct net_proto_family graft_family_ops = {
	.family	= PF_GRAFT,
	.create	= graft_create,
	.owner	= THIS_MODULE,
};


static int __init af_graft_init(void)
{
	int ret;

	ret = register_pernet_subsys(&graft_net_ops);
	if (ret)
		goto netns_failed;

	ret = genl_register_family(&graft_nl_family);
	if (ret)
		goto genl_failed;

	ret = proto_register(&graft_proto, 1);
	if (ret) {
		pr_err("%s: proto_register failed '%d'\n", __func__, ret);
		goto proto_register_failed;
	}

	ret = sock_register(&graft_family_ops);
	if (ret) {
		pr_err("%s: sock_register failed '%d'\n", __func__, ret);
		goto sock_register_failed;
	}

	pr_info("graft version (%s) is loaded\n", GRAFT_VERSION);

	return ret;

sock_register_failed:
	proto_unregister(&graft_proto);
proto_register_failed:
	genl_unregister_family(&graft_nl_family);
genl_failed:
	unregister_pernet_subsys(&graft_net_ops);
netns_failed:
	return ret;
}


static void __exit af_graft_exit(void)
{
	sock_unregister(PF_GRAFT);
	proto_unregister(&graft_proto);
	genl_unregister_family(&graft_nl_family);
	unregister_pernet_subsys(&graft_net_ops);

	pr_info("graft version (%s) is unloaded\n", GRAFT_VERSION);
}


module_init(af_graft_init);
module_exit(af_graft_exit);
MODULE_AUTHOR("Ryo Nakamura <upa@haeena.net>");
MODULE_LICENSE("GPL");
MODULE_VERSION(GRAFT_VERSION);
