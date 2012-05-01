// devmem.c (based on:)
// KernelMemoryAccess.c
// Amit Singh <osxbook.com>
//
// This source code is a part of the bonus content for the book
// Mac OS X Internals: A Systems Approach (ISBN 0321278542) by Amit Singh.
// Visit http://osxbook.com for details.
//
// A kernel extension that implements a read-only version of the traditional
// /dev/kmem character device, which provides access to kernel virtual memory.
// It also implements a dummy /dev/mem device that merely exists, without
// providing access to physical memory.
//
// This extension is intended for experimental/academic use on the x86-based
// version of Mac OS X, which does not provide these devices.
//

#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>

// The KPIs do not expose some things we need to compile this file. Change the
// "/work/xnu/" part below to the path of the xnu kernel source tree's root.
//
#include "/work/xnu/bsd/sys/uio_internal.h"

// We need kernel_pmap to do virtual->physical mappings for kernel memory.
// Since we don't need the internals of a struct pmap, the following works.
//
typedef struct pmap *pmap_t;
extern  pmap_t kernel_pmap;

// Yes, globals can be evil, but sometimes...
//
static int      devindex        = -1;     // our index in devfs
const char     *devmem_name     = "mem";
const int       devmem_minor    = 0;      // /dev/mem is (major, 0)
static void    *devmem_devnode  = NULL;   // devfs node for /dev/mem
const char     *devkmem_name    = "kmem";
const int       devkmem_minor   = 1;      // /dev/mem is (major, 1)
static void    *devkmem_devnode = NULL;   // devfs node for /dev/kmem

// Functions that we implement.
//
static boolean_t verify_access(off_t, size_t);
static int       cleanup(void);
static int       my_mmioctl(dev_t, u_long, caddr_t, int, struct proc *);
static int       my_mmread(dev_t, struct uio *, int ioflag);
static int       my_mmrw(dev_t, struct uio *, enum uio_rw);

// Other things that we use.
//
extern int seltrue(dev_t, int, struct proc *);
#define my_mmselect (select_fcn_t *)seltrue
#define nullopen    (d_open_t *)&nulldev
#define nullclose   (d_close_t *)&nulldev
#define nullread    (d_read_t *)&nulldev
#define nullwrite   (d_write_t *)&nulldev
#define nullioctl   (d_ioctl_t *)&nulldev
#define nullselect  (d_select_t *)&nulldev
#define nullstop    (d_stop_t *)&nulldev
#define nullreset   (d_reset_t *)&nulldev

// Our character device switch structure.
//
static struct cdevsw my_mm_cdevsw = {
    nullopen,        // open_close_fcn_t *d_open;
    nullclose,       // open_close_fcn_t *d_close;
    my_mmread,       // read_write_fcn_t *d_read;
    nullwrite,       // read_write_fcn_t *d_write;
    my_mmioctl,      // ioctl_fcn_t      *d_ioctl;
    nullstop,        // stop_fcn_t       *d_stop;
    nullreset,       // reset_fcn_t      *d_reset;
    0,               // struct tty      **d_ttys;
    my_mmselect,     // select_fcn_t     *d_select;
    eno_mmap,        // mmap_fcn_t       *d_mmap;
    eno_strat,       // strategy_fcn_t   *d_strategy;
    eno_getc,        // getc_fcn_t       *d_getc;
    eno_putc,        // putc_fcn_t       *d_putc;
    D_TTY,           // int               d_type;
};

// Ugliness note: we (implicitly) assume that KERN_SUCCESS is defined to
// be the value 0 (which it is).

// Verify that a given virtual memory range is valid.
//
boolean_t
verify_access(off_t start, size_t len)
{
    off_t base = trunc_page(start);
    off_t end  = start + len;
        
    while (base < end) {
        if (pmap_find_phys(kernel_pmap, (addr64_t)base) == (ppnum_t)0) {
            return FALSE;
        }
        base += page_size;
    }   

    return TRUE;
}

static int
my_mmread(dev_t dev, struct uio *uio, int ioflag)
{
    return my_mmrw(dev, uio, UIO_READ);
}

static int
my_mmioctl (__unused dev_t dev, u_long cmd, __unused caddr_t data,
           __unused int flag, __unused struct proc *p)
{
    switch (cmd) {
    case FIOASYNC:
    case FIONBIO:
        break;

    default:
        return ENODEV;
    }

    return 0;
}

static int
my_mmrw(dev_t dev, struct uio *uio, enum uio_rw rw)
{
    register u_int c;
    int error = 0;

    if (rw != UIO_READ) {
        return ENOTSUP;
    }

    while (uio_resid(uio) > 0 && error == 0) {
        if (uio_iov_len(uio) == 0) {
            uio_next_iov(uio);
            uio->uio_iovcnt--;
            if (uio->uio_iovcnt < 0) {
                panic("my_mmrw");
            }
            continue;
        }

        switch (minor(dev)) {
        // /dev/mem
        case 0:
            goto fault;

        // /dev/kmem
        case 1:
            c = uio_iov_len(uio);
            if (!verify_access(uio->uio_offset, c)) {
                goto fault;
            }
            error = uiomove((caddr_t)(uintptr_t)uio->uio_offset, (int)c, uio);
            continue;

        // We do not implement /dev/null (minor=2) and /dev/zero (minor=3).

        default:
            goto fault;
            break;
        }
            
        if (error) {
            break;
        }
        uio_iov_base_add(uio, c);
        uio_iov_len_add(uio, -((int)c));
        uio->uio_offset += c;
        uio_setresid(uio, (uio_resid(uio) - c));
    }

    return error;

fault:
    return EFAULT;
}

static int
cleanup(void)
{
    int ret = KERN_SUCCESS;

    if (devkmem_devnode != NULL) {
        devfs_remove(devkmem_devnode);
    }

    if (devmem_devnode != NULL) {
        devfs_remove(devmem_devnode);
    }

    if (devindex != -1) {
        ret = cdevsw_remove(devindex, &my_mm_cdevsw);
        if (ret != devindex) {
            printf("cdevsw_remove() failed (returned %d)\n", ret);
            ret = KERN_FAILURE;
        } else {
            ret = KERN_SUCCESS;
        }
    }

    return ret;
}

kern_return_t
devmem_start(kmod_info_t *ki, void *d)
{
    // Add the character device structure.
    devindex = cdevsw_add(-1, &my_mm_cdevsw);
    if (devindex == -1) {
        printf("cdevsw_add() failed\n");
        return KERN_FAILURE;
    }

    // Add the /dev/mem node.
    devmem_devnode = devfs_make_node(makedev(devindex, devmem_minor),
                                     DEVFS_CHAR,
                                     UID_ROOT,
                                     GID_KMEM,
                                     0640,
                                     devmem_name);
    if (devmem_devnode == NULL) {
        return cleanup();
    }

    // Add the /dev/kmem node.
    devkmem_devnode = devfs_make_node(makedev(devindex, devkmem_minor),
                                      DEVFS_CHAR,
                                      UID_ROOT,
                                      GID_KMEM,
                                      0640,
                                      devkmem_name);
    if (devkmem_devnode == NULL) {
        return cleanup();
    }
    
    return KERN_SUCCESS;
}

kern_return_t
devmem_stop(kmod_info_t *ki, void *d)
{
    return cleanup();
}
