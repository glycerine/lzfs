#include <linux/version.h>
#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <lzfs_inode.h>
#include <lzfs_xattr.h>
#include <linux/xattr.h>
#include <spl-debug.h>

#ifdef SS_DEBUG_SUBSYS
#undef SS_DEBUG_SUBSYS
#endif

/*
 *  Log LZFS debug messages as the spl SS_USER2 subsystem.
 */
#define SS_DEBUG_SUBSYS SS_USER2

int
lzfs_xattr_set(struct inode *inode, const char *name,
                    void *buffer, size_t size, const char *xattr_name)
{
    vnode_t *vp;
    vnode_t *dvp;
    vnode_t *xvp;
    vattr_t *vap;
    int err = 0;
    const cred_t *cred = get_current_cred();
    struct iovec iov = {
        .iov_base = buffer,
        .iov_len  = size,
    };

    uio_t uio = {
        .uio_iov     = &iov,
        .uio_resid   = size,
        .uio_iovcnt  = 1,
        .uio_loffset = (offset_t)0,
        .uio_limit   = MAXOFFSET_T,
        .uio_segflg  = UIO_SYSSPACE,
    };
	struct inode *xinode;

	dvp = LZFS_ITOV(inode);

    err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR | CREATE_XATTR_DIR,
             NULL, (cred_t *) cred, NULL, NULL, NULL);
    if(err)
        return -err;

    if(!buffer) {
        err = zfs_remove(vp, (char *)name, (cred_t *)cred, NULL, 0);
        return -err;
    }

    vap = kmalloc(sizeof(vattr_t), GFP_KERNEL);
    ASSERT(vap != NULL);
    memset(vap, 0, sizeof(vap));
    vap->va_type = VREG;
    vap->va_mode = 0644;
    vap->va_mask = AT_TYPE|AT_MODE;
    vap->va_uid = current_fsuid();
    vap->va_gid = current_fsgid();

    err = zfs_create(vp, (char *) xattr_name, vap, 0, 0644,
            &xvp, (cred_t *)cred, 0, NULL, NULL);
    kfree(vap);
	xinode = LZFS_VTOI(xvp);
    if(err) {
		unlock_new_inode(xinode);
		iput(xinode);
        return -err;
	}
    err = zfs_write(xvp, &uio, 0, (cred_t *)cred, NULL);
    (void)put_cred(cred);

	unlock_new_inode(xinode);
	return (err ? -err : 0);
}

int
lzfs_xattr_get(struct inode *inode, const char *name,
                    void *buffer, size_t size, const char *xattr_name)
{
	struct inode *xinode = NULL;
	vnode_t *vp;
	vnode_t *dvp;
	vnode_t *xvp;
	int err = 0;
	const cred_t *cred = get_current_cred();
	struct iovec iov;
	uio_t uio;

	dvp = LZFS_ITOV(inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR, NULL,
			(cred_t *) cred, NULL, NULL, NULL);
        if(err) {
            if(err == ENOENT) {
                return -ENODATA;
            }
            return -err;
        }
	ASSERT(vp != NULL);
	err = zfs_lookup(vp, (char *) xattr_name, &xvp, NULL, 0, NULL,
	(cred_t *) cred, NULL, NULL, NULL);
	if(err) {
		if(err == ENOENT) {
		    return -ENODATA;
		}
		return -err;
	}
	xinode = LZFS_VTOI(xvp);
	if(!size) {
		return ((int) xinode->i_size);
	}
	iov.iov_base = buffer;
	iov.iov_len = size;
	uio.uio_iov = &iov;
	uio.uio_resid = size;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = (offset_t)0;
	uio.uio_segflg  = UIO_SYSSPACE;

	err = zfs_read(xvp, &uio, 0, (cred_t *)cred, NULL);
	(void)put_cred(cred);
	if(err) {
		return -err;
	}

	return size - uio.uio_resid;
}

#define for_each_xattr_handler(handlers, handler)	\
		for ((handler) = *(handlers)++;		\
			(handler) != NULL;		\
			(handler) = *(handlers)++)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static inline struct xattr_handler *
find_xattr_handler_prefix(struct xattr_handler **handlers,
				const char *name)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static inline const struct xattr_handler *
find_xattr_handler_prefix(const struct xattr_handler **handlers,
				const char *name)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	struct xattr_handler *ea_handler;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	const struct xattr_handler *ea_handler;
#endif

	if (!handlers) {
		return NULL;
	}
	for_each_xattr_handler(handlers, ea_handler) {
		if (strncmp(ea_handler->prefix, name, 
			strlen(ea_handler->prefix)) == 0)
			break;
	}
	return ea_handler;
}

struct listxattr_buf {
	size_t size;
	size_t pos;
	char *buf;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	struct inode *inode;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	struct dentry *dentry;
#endif
};

static int listxattr_filler(void *buf, const char *name, int namelen,
                            loff_t offset, u64 ino, unsigned int d_type)
{
	struct listxattr_buf *b = (struct listxattr_buf *)buf;
	size_t size = 0;
	
	if (name[0] != '.' ||
		(namelen != 1 && (name[1] != '.' || namelen != 2))) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
			struct xattr_handler *handler;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
			const struct xattr_handler *handler;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			handler = find_xattr_handler_prefix(
					b->inode->i_sb->s_xattr,
					name);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
			handler = find_xattr_handler_prefix(
                                        b->dentry->d_sb->s_xattr,
                                        name);
#endif
			if (!handler)
				return 0;
			if (b->buf) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
				size = handler->list(b->inode, b->buf + b->pos,
						b->size, name, namelen);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
				size = handler->list(b->dentry, b->buf + b->pos,
                                                b->size, name, namelen,
						handler->flags);
#endif
				if (size > b->size)
					return -ERANGE;
			} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)				
					size = handler->list(b->inode, NULL, 
						0, name, namelen);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
					size = handler->list(b->dentry, NULL,
                                                0, name, namelen, handler->flags);
#endif
			}
	}
	b->pos += size;
	return 0;
}

ssize_t
lzfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	vnode_t *dvp;
	vnode_t *vp; /* xattr dir vnode pointer */
	int err = 0, eof;
	const cred_t *cred = get_current_cred();
	loff_t pos = 0;

	struct listxattr_buf buf = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.inode = dentry->d_inode,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
		.dentry = dentry,
#endif
		.buf = buffer,
		.size = buffer ? size : 0,
	};

	dvp = LZFS_ITOV(dentry->d_inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR, NULL,
			(cred_t *) cred, NULL, NULL, NULL);
	if(err) {
		if(err == ENOENT) {
			err = 0;
		}
		return -err;
	}
	ASSERT(vp != NULL);

	if(!size)
		return (LZFS_VTOI(vp))->i_size;
	err = zfs_readdir(vp, (void *)&buf, NULL, &eof, NULL, 0, 
			listxattr_filler, &pos);
	if(err)
		return -err;
	else
		err = buf.pos;
	return err;
}

int
lzfs_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)	
	struct xattr_handler *handler;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	const struct xattr_handler *handler;
#endif
	handler = find_xattr_handler_prefix(inode->i_sb->s_xattr, name);

	if (!handler)
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	return handler->set(inode, name, NULL, 0, XATTR_REPLACE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	return handler->set(dentry, name, NULL, 0, XATTR_REPLACE, 
				handler->flags);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
struct xattr_handler *lzfs_xattr_handlers[] = {
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
const struct xattr_handler *lzfs_xattr_handlers[] = {
#endif
	&lzfs_xattr_user_handler,
#ifdef HAVE_ZPL	
	&lzfs_xattr_trusted_handler,	// TODO
#endif /* HAVE_ZPL */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,31)
	&lzfs_xattr_acl_access_handler,
	&lzfs_xattr_acl_default_handler,
#endif
	&lzfs_xattr_security_handler,
        NULL
};
