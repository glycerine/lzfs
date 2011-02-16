#include <linux/version.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>
#include <linux/slab.h>

#include <sys/vnode.h>
#include <sys/vfs.h>

#include <lzfs_xattr.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,31)
static int lzfs_set_mode(struct inode *inode, mode_t mode)
{
	struct iattr *att;
	struct dentry *fake_de = NULL;
	int err = -ENOMEM;

	att = kzalloc(sizeof(struct iattr), GFP_KERNEL);
	if(att == NULL)
		goto out;

	fake_de = kzalloc(sizeof(struct dentry), GFP_KERNEL);
	if(fake_de == NULL)
		goto out;

	fake_de->d_inode = inode;
	att->ia_valid    = ATTR_MODE;
	att->ia_mode     = mode;
	err = lzfs_vnop_setattr(fake_de, att);
out:
	if (att)
		kfree(att);
	if (fake_de)
		kfree(fake_de);
	return err;

}

static int
lzfs_set_acl(struct inode *inode,struct posix_acl *acl, int type)
{
	int err = 0;
	size_t size=0;

	char *xattr_name = NULL;
	char * value = NULL;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	switch(type) {
		case ACL_TYPE_ACCESS:
			xattr_name = POSIX_ACL_XATTR_ACCESS;
			if (acl) {
				mode_t mode = inode->i_mode;
				err = posix_acl_equiv_mode(acl, &mode);
				if (err < 0)
					return err;
				else {
					if (inode->i_mode != mode) {
						int rc;
						rc = lzfs_set_mode(inode,mode);
						if (rc) {
							/* XXX error handling */
						}
					}
					if (err == 0) {
						/* not extended attribute */
						acl = NULL;
					}
				}
			}
			break;

		case ACL_TYPE_DEFAULT:
			xattr_name = POSIX_ACL_XATTR_DEFAULT;
			if (!S_ISDIR(inode->i_mode))
				return acl ? -EACCES : 0;
			break;

		default:
			return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_KERNEL);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);

		err = posix_acl_to_xattr(acl, value, size);
		if (err < 0)
			goto out;
	}

	err = lzfs_xattr_set(inode, xattr_name, value, size, xattr_name);

	if (err == -ENOENT && !acl)
		err = 0;
	if (!err) {
		if (acl)
			set_cached_acl(inode, type, acl);
		else
			forget_cached_acl(inode, type);
	}
//	posix_acl_release(acl);

out:
	if (value)
		kfree(value);
	return err;

}


static struct posix_acl *
lzfs_get_acl(struct inode *inode, int type)
{
	char *name;
	char *xattr_name;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;

	acl = get_cached_acl(inode, type);
	if (acl != ACL_NOT_CACHED)
		return acl;

	switch (type) {
		case ACL_TYPE_ACCESS:
			name = POSIX_ACL_XATTR_ACCESS;
			break;
		case ACL_TYPE_DEFAULT:
			name = POSIX_ACL_XATTR_DEFAULT;
			break;
		default:
			BUG();
	}

	xattr_name = kmalloc(strlen(name), GFP_NOFS);
	if (!xattr_name)
		return ERR_PTR(-ENOMEM);
	xattr_name = strncpy(xattr_name, name,strlen(name));

	retval = lzfs_xattr_get(inode, name, NULL, 0, xattr_name);
	if (retval > 0) {
		value = kmalloc(retval, GFP_NOFS);
		if (!value) {
			kfree(xattr_name);
			return ERR_PTR(-ENOMEM);
		}
		retval = lzfs_xattr_get(inode, name, value, retval, xattr_name);
	}
	kfree(xattr_name);

	if (retval > 0)
		acl = posix_acl_from_xattr(value, retval);
	
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(retval);

	if (value)
		kfree(value);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

int
lzfs_acl_init(struct inode *inode, struct inode *dir)
{
	struct posix_acl *acl = NULL;
	int error = 0;

	if (!S_ISLNK(inode->i_mode)) {
		acl = lzfs_get_acl(dir, ACL_TYPE_DEFAULT);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		if (!acl) {
			inode->i_mode &= ~current_umask();
			error = lzfs_set_mode(inode,inode->i_mode);
			if (error)
				goto cleanup;
		}
	}

	if (acl) {
		struct posix_acl *clone;
		mode_t mode;

		if (S_ISDIR(inode->i_mode)) {
			error = lzfs_set_acl(inode, acl, ACL_TYPE_DEFAULT);
			if (error < 0)
				goto cleanup;
		}
		clone = posix_acl_clone(acl, GFP_NOFS);
		error = -ENOMEM;
		if (!clone)
			goto cleanup;

		mode = inode->i_mode;
		error = posix_acl_create_masq(clone, &mode);
		if (error >= 0) {
			int err;
			inode->i_mode = mode;
			err = lzfs_set_mode(inode, mode);
			if (error > 0) {
				/* This is an extended ACL */
				error = lzfs_set_acl(inode, clone, ACL_TYPE_ACCESS);
			}
			error |= err;
		}
		posix_acl_release(clone);
	}
cleanup:
	posix_acl_release(acl);
	return error;
}

int
lzfs_check_acl(struct inode *inode, int mask)
{
	struct posix_acl *acl = lzfs_get_acl(inode, ACL_TYPE_ACCESS);

	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl) {
		int error = posix_acl_permission(inode, acl, mask);
		posix_acl_release(acl);
		return error;
	}
	return -EAGAIN;
}

int
lzfs_acl_chmod(struct inode *inode)
{
	struct posix_acl *acl, *clone;
	int error;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	acl = lzfs_get_acl(inode, ACL_TYPE_ACCESS);
	if (IS_ERR(acl) || !acl)
		return PTR_ERR(acl);
	clone = posix_acl_clone(acl, GFP_KERNEL);
	posix_acl_release(acl);
	if (!clone)
		return -ENOMEM;
	error = posix_acl_chmod_masq(clone, inode->i_mode);
	if (!error)
		error = lzfs_set_acl(inode, clone, ACL_TYPE_ACCESS);
	posix_acl_release(clone);
	return error;

}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static inline size_t
lzfs_xattr_acl_list_access(struct inode *inode, char *list, 
		size_t list_size,const char *name, size_t name_len)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static inline size_t
lzfs_xattr_acl_list_access(struct dentry *dentry, char *list, 
		size_t list_size,const char *name, size_t name_len,int type)
#endif
{
	const size_t total_len = sizeof(POSIX_ACL_XATTR_ACCESS);

	if (list && total_len <= list_size)
		memcpy(list, POSIX_ACL_XATTR_ACCESS, total_len);
	return total_len;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static inline size_t
lzfs_xattr_acl_list_default(struct inode *inode, char *list, size_t list_size,
		const char *name, size_t name_len)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static inline size_t
lzfs_xattr_acl_list_default(struct dentry *dentry, char *list, size_t list_size,
		const char *name, size_t name_len,int type)
#endif
{
	const size_t total_len = sizeof(POSIX_ACL_XATTR_DEFAULT);

	if (list && total_len <= list_size)
		memcpy(list, POSIX_ACL_XATTR_DEFAULT,total_len);
	return total_len;
}


static int
lzfs_xattr_acl_get(struct dentry *dentry, const char *name, void *buffer, 
		size_t size, int type)
{
	struct posix_acl *acl;
	int error;

	if (strcmp(name, "") != 0)
		return -EINVAL;

	acl = lzfs_get_acl(dentry->d_inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;

	error = posix_acl_to_xattr(acl, buffer, size);
	posix_acl_release(acl);
	return error;
}

static int
lzfs_xattr_acl_set(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags, int type)
{
	struct posix_acl * acl = NULL;
	int err = 0;

	if ((strcmp(name, "") != 0) && 
			((type != ACL_TYPE_ACCESS) && (type != ACL_TYPE_DEFAULT)))
		return -EINVAL;

	if (!is_owner_or_cap(dentry->d_inode))
		return -EPERM;

	if (value) {
		acl = posix_acl_from_xattr(value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		else if (acl) {
			err = posix_acl_valid(acl);
			if (err)
				goto release_and_out;
		}
	}

	err = lzfs_set_acl(dentry->d_inode, acl, type);
release_and_out:
	posix_acl_release(acl);
	return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static inline int
__lzfs_xattr_acl_get(struct inode *inode, const char *name,
		        void *buffer, size_t size, int type)
{
	struct dentry *fake_de = NULL;
	int error;

	fake_de = kzalloc(sizeof(struct dentry), GFP_KERNEL);
	if (!fake_de)
		return -ENOMEM;

	fake_de->d_inode = inode;
	error = lzfs_xattr_acl_get(fake_de, "", buffer, size, type);
	kfree(fake_de);

	return error;

}

static inline int
lzfs_xattr_acl_get_access(struct inode *inode, const char *name,
		void *buffer, size_t size)
{
	return __lzfs_xattr_acl_get(inode, name, buffer, size, ACL_TYPE_ACCESS);
}

static inline int
__lzfs_xattr_acl_set(struct inode *inode, const char *name,
		        const void *buffer, size_t size, int type, int flags)
{
	struct dentry *fake_de = NULL;
	int error;

	fake_de = kzalloc(sizeof(struct dentry), GFP_KERNEL);
	if (!fake_de)
		return -ENOMEM;

	fake_de->d_inode = inode;
	error = lzfs_xattr_acl_set(fake_de, "", buffer, size, flags, type);
	kfree(fake_de);

	return error;

}

static inline int
lzfs_xattr_acl_set_access(struct inode *inode, const char *name,
		const void *buffer, size_t size, int flags)
{
	return __lzfs_xattr_acl_set(inode, name, buffer, size, ACL_TYPE_ACCESS, flags);
}
#endif

struct xattr_handler lzfs_xattr_acl_access_handler =
{
    .prefix = POSIX_ACL_XATTR_ACCESS,
    .list   = lzfs_xattr_acl_list_access,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
    .get    = lzfs_xattr_acl_get_access,
    .set    = lzfs_xattr_acl_set_access,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
    .get    = lzfs_xattr_acl_get,
    .set    = lzfs_xattr_acl_set,
    .flags  = ACL_TYPE_ACCESS,
#endif
};


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static inline int
lzfs_xattr_acl_get_default(struct inode *inode, const char *name,
		void *buffer, size_t size)
{
	return __lzfs_xattr_acl_get(inode, name, buffer, size, ACL_TYPE_DEFAULT);
}

static inline int
lzfs_xattr_acl_set_default(struct inode *inode, const char *name,
		const void *buffer, size_t size, int flags)
{
	return __lzfs_xattr_acl_set(inode, name, buffer, size, ACL_TYPE_DEFAULT, flags);
}
#endif

struct xattr_handler lzfs_xattr_acl_default_handler =
{
	.prefix = POSIX_ACL_XATTR_DEFAULT,
	.list   = lzfs_xattr_acl_list_default,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	.get    = lzfs_xattr_acl_get_default,
	.set    = lzfs_xattr_acl_set_default,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	.get    = lzfs_xattr_acl_get,
	.set    = lzfs_xattr_acl_set,
	.flags  = ACL_TYPE_DEFAULT,
#endif
};

#endif
