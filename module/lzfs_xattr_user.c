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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static int
lzfs_xattr_user_get(struct inode *inode, const char *name,
			void *buffer, size_t size)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static int
lzfs_xattr_user_get(struct dentry *dentry, const char *name,
			void *buffer, size_t size, int type)
#endif
{
	char *xattr_name;
	int rc;

	if(strcmp(name,"") == 0) {
		return -EINVAL;
	}

    xattr_name = kzalloc(strlen(name) + 6, GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;

	xattr_name = strncpy(xattr_name, "user.", 5);
	xattr_name = strncat(xattr_name, name, strlen(name));

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)	
	rc = lzfs_xattr_get(inode, name, buffer, size, xattr_name);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	rc = lzfs_xattr_get(dentry->d_inode, name, buffer, size, xattr_name);
#endif
	kfree(xattr_name);
	return rc;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static int      
lzfs_xattr_user_set(struct inode *inode, const char *name,
			const void *value, size_t size, int flags)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static int
lzfs_xattr_user_set(struct dentry *dentry, const char *name,
			const void *value, size_t size, int flags, int type)
#endif
{
	char *xattr_name;
	int rc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	struct inode *inode = dentry->d_inode;
#endif
	xattr_name = kzalloc(strlen(name) + 6, GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	xattr_name = strncpy(xattr_name, "user.", 5);
	xattr_name = strncat(xattr_name, name, strlen(name));
	rc = lzfs_xattr_set(inode, name, (void *) value, size, xattr_name);
	kfree(xattr_name);
	return rc;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static size_t
lzfs_xattr_user_list(struct inode *inode, char *list, size_t list_size,
			const char *name, size_t name_len)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
static size_t
lzfs_xattr_user_list(struct dentry *dentry, char *list, size_t list_size,
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


struct xattr_handler lzfs_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.list   = lzfs_xattr_user_list,
	.get    = lzfs_xattr_user_get,
	.set    = lzfs_xattr_user_set,
};
