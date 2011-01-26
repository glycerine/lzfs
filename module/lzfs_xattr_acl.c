#include <linux/version.h>
#include <linux/fs.h>

#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <lzfs_inode.h>
#include <lzfs_xattr.h>
#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>
#include <spl-debug.h>

#ifdef SS_DEBUG_SUBSYS
#undef SS_DEBUG_SUBSYS
#endif

/*
 *  Log LZFS debug messages as the spl SS_USER2 subsystem.
 */
#define SS_DEBUG_SUBSYS SS_USER2

#define MAX_ACL_SIZE 10000						  //arbitrarily chosen.

static struct posix_acl *
lzfs_get_acl(struct inode *inode, int type)
{
	char* name;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;
	acl = get_cached_acl(inode, type);
	if (acl != ACL_NOT_CACHED)
		return acl;

	switch (type)
	{
		case ACL_TYPE_ACCESS:
			name = POSIX_ACL_XATTR_ACCESS;
			break;
		case ACL_TYPE_DEFAULT:
			name = POSIX_ACL_XATTR_DEFAULT;
			break;
		default:
			BUG();
	}

	retval = lzfs_xattr_get(inode, name, NULL, 0,2);
	if (retval > 0)
	{
		value = kmalloc(retval, GFP_NOFS);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = lzfs_xattr_get(inode, name, value, retval,2);
	}
	if (retval > 0)
	{
		acl = posix_acl_from_xattr(value, retval);
	}
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(retval);
	if(value){kfree(value);}
	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}


static int
lzfs_xattr_acl_get(struct dentry *dentry, const char *name,
void *buffer, size_t size, int type)
{

	struct posix_acl *acl;
	int error;

	acl = lzfs_get_acl(dentry->d_inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;
	error = posix_acl_to_xattr(acl, buffer, size);
	posix_acl_release(acl);

	return error;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static int
lzfs_xattr_acl_get_default(struct inode *inode, const char *name,
void *buffer, size_t size)
{
	struct dentry* fake_de;
	int retval;
	fake_de = kmalloc(sizeof(struct dentry), GFP_KERNEL);
	if(fake_de == NULL){return -ENOMEM;}
	fake_de->d_inode=inode;
	retval=lzfs_xattr_acl_get(fake_de,NULL,buffer,size,ACL_TYPE_DEFAULT);
	kfree(fake_de);
	return retval;
}


static int
lzfs_xattr_acl_get_access(struct inode *inode, const char *name,
void *buffer, size_t size)
{
	struct dentry* fake_de;
	int retval;
	fake_de = kmalloc(sizeof(struct dentry), GFP_KERNEL);
	if(fake_de == NULL){return -ENOMEM;}
	fake_de->d_inode=inode;
	retval=lzfs_xattr_acl_get(fake_de,NULL,buffer,size,ACL_TYPE_ACCESS);
	kfree(fake_de);
	return retval;
}
#endif

static int lzfs_set_mode(struct inode *inode,mode_t mode)
{
	struct iattr* att;
	struct dentry* fake_de;
	int err;
	att = kmalloc(sizeof(struct iattr), GFP_KERNEL);
	fake_de = kmalloc(sizeof(struct dentry), GFP_KERNEL);
	if(att == NULL){return -ENOMEM;}
	if(fake_de == NULL){return -ENOMEM;}
	fake_de->d_inode=inode;
	att->ia_valid=ATTR_MODE;
	att->ia_mode=mode;
	err=lzfs_vnop_setattr(fake_de,att);
	kfree(att);
	kfree(fake_de);
	if(err <0){return err;}
	return 0;

}


static int lzfs_set_acl(struct inode *inode,struct posix_acl *acl, int type)
{
	vnode_t *vp;
	vnode_t *dvp;
	vnode_t *xvp;
	vattr_t *vap;
	int err = 0;
	size_t size=0;
	const struct cred *cred = get_current_cred();
	struct iovec iov;

	char *xattr_name = NULL;
	char * value = NULL;
	uio_t uio =
	{
		.uio_iov     = &iov,
		.uio_iovcnt  = 1,
		.uio_loffset = (offset_t)0,
		.uio_limit   = MAXOFFSET_T,
		.uio_segflg  = UIO_SYSSPACE,
	};
	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	switch(type)
	{
		case ACL_TYPE_ACCESS:
			xattr_name = POSIX_ACL_XATTR_ACCESS;
			if (acl)
			{
				mode_t mode = inode->i_mode;
				err = posix_acl_equiv_mode(acl, &mode);
				if (err < 0)
					return err;
				else
				{
					if(inode->i_mode!=mode){lzfs_set_mode(inode,mode);}
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
	if (acl)
	{
		value = kmalloc(MAX_ACL_SIZE, GFP_KERNEL);
		size=posix_acl_to_xattr(acl,value, MAX_ACL_SIZE);
		iov.iov_base = (void *) value;
		iov.iov_len  = size;
		uio.uio_resid=size;

		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}
	else
		{value=NULL;}

		dvp = LZFS_ITOV(inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR | CREATE_XATTR_DIR,
		NULL, (struct cred *) cred, NULL, NULL, NULL);
	if(err)
	{
		return -err;
	}
	if(!value)
	{
		err =zfs_remove(vp, (char *) xattr_name,
			(struct cred *)cred, NULL, 0);
		if(err==2){err=0;}
		if(err==0){forget_cached_acl(inode,type);}
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
	err = zfs_create(vp, xattr_name, vap, 0, 0644,
		&xvp, (struct cred *)cred, 0, NULL, NULL);
	kfree(vap);

	if(err)
	{
		return -err;
	}
	err = zfs_write(xvp, &uio, 0, (cred_t *)cred, NULL);
	put_cred(cred);
	set_cached_acl(inode, type, acl);
	posix_acl_release(acl);
	if(value){kfree(value);}
	if(err)
	{
		return -err;
	}
	return err;

}


static int
lzfs_xattr_acl_set(struct dentry *dentry, const char *name,
const void *value, size_t size, int flags, int type)

{
	struct posix_acl * acl;
	int err=0;

	if ((strcmp(name, "") != 0) && ((type != ACL_TYPE_ACCESS) && (type != ACL_TYPE_DEFAULT)))
	{
		return -EINVAL;

	}
	if (!is_owner_or_cap(dentry->d_inode))
		return -EPERM;

	if (value)
	{
		acl = posix_acl_from_xattr(value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		else if (acl)
		{
			err = posix_acl_valid(acl);
			if (err <0)
				return err;
		}
	}
	else
	{
		acl = NULL;
	}
	return lzfs_set_acl(dentry->d_inode,acl,type);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static int
lzfs_xattr_acl_set_default(struct inode *inode, const char *name,
const void *value, size_t size, int flags)
{
	struct dentry* fake_de;
	int retval;
	fake_de = kmalloc(sizeof(struct dentry), GFP_KERNEL);
	if(fake_de == NULL){return -ENOMEM;}
	fake_de->d_inode=inode;
	retval=lzfs_xattr_acl_set(fake_de,name,value,size,0,ACL_TYPE_DEFAULT);
	kfree(fake_de);
	return retval;
}


static int
lzfs_xattr_acl_set_access(struct inode *inode, const char *name,
const void *value, size_t size, int flags)
{
	struct dentry* fake_de;
	int retval;
	fake_de = kmalloc(sizeof(struct dentry), GFP_KERNEL);
	if(fake_de == NULL){return -ENOMEM;}
	fake_de->d_inode=inode;
	retval=lzfs_xattr_acl_set(fake_de,name,value,size,0,ACL_TYPE_ACCESS);
	kfree(fake_de);
	return retval;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static size_t
lzfs_xattr_acl_list_access(struct inode *inode, char *list, size_t list_size,const char *name, size_t name_len)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static size_t
lzfs_xattr_acl_list_access(struct dentry *dentry, char *list, size_t list_size,const char *name, size_t name_len,int type)
#endif
{
	const size_t total_len = sizeof(POSIX_ACL_XATTR_ACCESS);

	if (list && total_len <= list_size)
	{
		memcpy(list, POSIX_ACL_XATTR_ACCESS, total_len);
	}
	return total_len;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static size_t
lzfs_xattr_acl_list_default(struct inode *inode, char *list, size_t list_size,const char *name, size_t name_len)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static size_t
lzfs_xattr_acl_list_default(struct dentry *dentry, char *list, size_t list_size,const char *name, size_t name_len,int type)
#endif
{
	const size_t total_len = sizeof(POSIX_ACL_XATTR_DEFAULT);

	if (list && total_len <= list_size)
	{
		memcpy(list, POSIX_ACL_XATTR_DEFAULT,total_len);
	}
	return total_len;
}


int
lzfs_check_acl(struct inode *inode, int mask)
{

	struct posix_acl *acl = lzfs_get_acl(inode, ACL_TYPE_ACCESS);

	if (IS_ERR(acl))
	{
		return PTR_ERR(acl);
	}
	if (acl)
	{
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
	{
		error = lzfs_set_acl(inode,clone, ACL_TYPE_ACCESS);
	}
	return error;
}


int
lzfs_acl_init(struct inode *inode, struct inode *dir)
{
	struct posix_acl *acl = NULL;
	int error = 0;
	if (!S_ISLNK(inode->i_mode))
	{
		acl = lzfs_get_acl(dir, ACL_TYPE_DEFAULT);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		if (!acl)
		{
			inode->i_mode &= ~current_umask();
			lzfs_set_mode(inode,inode->i_mode);
		}
	}
	if (acl)
	{
		struct posix_acl *clone;
		mode_t mode;

		if (S_ISDIR(inode->i_mode))
		{
			error = lzfs_set_acl(inode,acl,ACL_TYPE_DEFAULT);
			if (error<0)
				goto cleanup;
		}
		clone = posix_acl_clone(acl, GFP_NOFS);
		error = -ENOMEM;
		if (!clone)
			goto cleanup;

		mode = inode->i_mode;
		error = posix_acl_create_masq(clone, &mode);
		if (error >= 0)
		{
			inode->i_mode = mode;
			if (error > 0)
			{
/* This is an extended ACL */
				error = lzfs_set_acl(inode,clone, ACL_TYPE_ACCESS);
				if(error <0){return error;}
			}
			error=lzfs_set_mode(inode,mode);

		}
	}

	cleanup:
//posix_acl_release(acl);
	return error;
}


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
