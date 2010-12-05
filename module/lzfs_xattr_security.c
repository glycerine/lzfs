#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/lzfs_inode.h>
#include <sys/lzfs_xattr.h>
#include <linux/xattr.h>
#include <linux/security.h>

static int
lzfs_xattr_security_get(struct inode *inode, const char *name,
                    void *buffer, size_t size)
{

	if(strcmp(name,"") == 0) {
		return -EINVAL;
	}

	return lzfs_xattr_get(inode, name, buffer, size, 1); // 1 for security SELinux

//	return -ENOTSUP;
}

static int      
lzfs_xattr_security_set(struct inode *inode, const char *name,
                    const void *value, size_t size, int flags)
{               

	vnode_t *vp;
	vnode_t *dvp;
	vnode_t *xvp;
	vattr_t *vap;
	int err = 0;
	const struct cred *cred = get_current_cred();
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len  = size,
	};

	char *xattr_name = NULL;	
	uio_t uio = {
		.uio_iov     = &iov,
		.uio_resid   = size,
		.uio_iovcnt  = 1,
		.uio_loffset = (offset_t)0,
		.uio_limit   = MAXOFFSET_T,
		.uio_segflg  = UIO_SYSSPACE,
	};

	printk(" \n\n hello \n\n");
	
	dvp = LZFS_ITOV(inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR | CREATE_XATTR_DIR,
			 NULL, (struct cred *) cred, NULL, NULL, NULL);
	if(err) {
		return -err;
	}
	
	if(!value) {
		err =zfs_remove(vp, (char *) name,
			(struct cred *)cred, NULL, 0);
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
			&xvp, (struct cred *)cred, 0, NULL, NULL);
	kfree(vap);
	kfree(xattr_name);
	if(err) {
		return -err;
	}
	err = zfs_write(xvp, &uio, 0, (cred_t *)cred, NULL);
	put_cred(cred);
	if(err) {
		return -err;
	}
	return -err;

//	return -ENOTSUP;
}

static size_t
lzfs_xattr_security_list(struct inode *inode, char *list, size_t list_size,
                        const char *name, size_t name_len)
{

	const size_t total_len = name_len + 1;

	if (list && total_len <= list_size) {
		memcpy(list, name, name_len);
		list[name_len] = '\0';
	}
	return total_len;

//	return -ENOTSUP;
}


int
lzfs_init_security(struct inode *inode, struct inode *dir)
{
        int err;
        size_t len;
        void *value;
        char *name;

        err = security_inode_init_security(inode, dir, &name, &value, &len);
        if (err) {
                if (err == -EOPNOTSUPP)
                        return 0;
                return err;
        }

        err = lzfs_xattr_security_set(inode, name, value, len, 0);
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

