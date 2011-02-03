#include <linux/version.h>
#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <lzfs_inode.h>
#include <lzfs_xattr.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <spl-debug.h>

#ifdef SS_DEBUG_SUBSYS
#undef SS_DEBUG_SUBSYS
#endif

/*
 *  Log LZFS debug messages as the spl SS_USER2 subsystem.
 */
#define SS_DEBUG_SUBSYS SS_USER2

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static int
lzfs_xattr_security_get(struct inode *inode, const char *name,
			void *buffer, size_t size)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static int
lzfs_xattr_security_get(struct dentry *dentry, const char *name,
			void *buffer, size_t size, int type)
#endif
{
	if(strcmp(name,"") == 0) {
		return -EINVAL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	return lzfs_xattr_get(inode, name, buffer, size, 1); // 1 for security SELinux
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	return lzfs_xattr_get(dentry->d_inode, name, buffer, size, 1);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static int      
lzfs_xattr_security_set(struct inode *inode, const char *name,
                    const void *value, size_t size, int flags)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static int
lzfs_xattr_security_set(struct dentry *dentry, const char *name,
                    const void *value, size_t size, int flags, int type)
#endif
{
	vnode_t *vp;
	vnode_t *dvp;
	vnode_t *xvp;
	vattr_t *vap;
	int err = 0;
	const cred_t *cred = get_current_cred();
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len  = size,
	};

	char *xattr_name = NULL;
	uio_t uio = {
		.uio_iov = &iov,
		.uio_resid = size,
		.uio_iovcnt = 1,
		.uio_loffset = (offset_t)0,
		.uio_limit = MAXOFFSET_T,
		.uio_segflg = UIO_SYSSPACE,
	};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	dvp = LZFS_ITOV(inode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	dvp = LZFS_ITOV(dentry->d_inode);
#endif
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR | CREATE_XATTR_DIR,
			 NULL, (cred_t *) cred, NULL, NULL, NULL);
	if(err) {
		return -err;
	}
	
	if(!value) {
		err =zfs_remove(vp, (char *) name,
			(cred_t *)cred, NULL, 0);
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
	xattr_name = kzalloc(strlen(name) + 10, GFP_KERNEL);
	xattr_name = strncpy(xattr_name, "security.", 9);
	xattr_name = strncat(xattr_name, name, strlen(name));

	err = zfs_create(vp, xattr_name, vap, 0, 0644,
			&xvp, (cred_t *)cred, 0, NULL, NULL);
	kfree(vap);
	kfree(xattr_name);
	if(err) {
		return -err;
	}
	err = zfs_write(xvp, &uio, 0, (cred_t *)cred, NULL);
	(void)put_cred(cred);
	if(err) {
		return -err;
	}
	return -err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static size_t
lzfs_xattr_security_list(struct inode *inode, char *list, size_t list_size,
				const char *name, size_t name_len)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static size_t
lzfs_xattr_security_list(struct dentry *dentry, char *list, size_t list_size,
				const char *name, size_t name_len, int type)
#endif
{

	const size_t total_len = name_len + 1;

	if (list && total_len <= list_size) {
		memcpy(list, name, name_len);
		list[name_len] = '\0';
	}
	return total_len;
}

int
lzfs_init_security(struct dentry *dentry, struct inode *dir)
{
	int err;
	size_t len;
	void *value;
	char *name;

	err = security_inode_init_security(dentry->d_inode, dir, &name, &value, &len);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	err = lzfs_xattr_security_set(dentry->d_inode, name, value, len, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	err = lzfs_xattr_security_set(dentry, name, value, len, 0, 0);
#endif
	kfree(name);
	kfree(value);
	return err;
}

struct xattr_handler lzfs_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.list   = lzfs_xattr_security_list,
	.get    = lzfs_xattr_security_get,
	.set    = lzfs_xattr_security_set,
};
