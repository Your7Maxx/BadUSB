#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/errno.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/string.h>

#define __LOWER(x) (x & 0xffffffff)
#define __UPPER(x) (x >> 32)

struct data_t {
    u32 pid;
    char filename[50];
    int file_len;
};

struct path_t{
    char pathname[100];
    int path_len;
    int flag;
};

BPF_TABLE_PUBLIC("extern", u32, struct path_t, path_table, 1);

LSM_PROBE(file_open,struct file *file){

    int i,j;
    struct data_t data = {};
    struct dentry *dentry;
    dentry = file->f_path.dentry;

    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), dentry->d_parent->d_parent->d_parent->d_parent->d_name.name);
    u32 id = 1;
    struct path_t *path_tmp = path_table.lookup(&id);

    if(path_tmp) {

    if(path_tmp->flag){
    for(i=0; i<15; i++){
        for(j=0; j<9; j++){
            if(data.filename[i+j] != path_tmp->pathname[j])
                break;
        }
        if(j == 9){
            bpf_trace_printk("Deny->filename:%s",data.filename);
            bpf_trace_printk("Deny->pathname:%s",path_tmp->pathname);
            return -EPERM;
            }
        }
    }else{
        bpf_trace_printk("Allow->filename:%s",data.filename);
        bpf_trace_printk("Allow->pathname:%s",path_tmp->pathname);
        return 0;
    }

    return 0;
}

    return 0;

}
