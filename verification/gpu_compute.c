/* Tiny real CUDA kernel test: no CUDA toolkit or Python packages needed in the guest. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define LOAD(name) void *name = dlsym(lib, #name); if (!name) {fprintf(stderr,"missing %s\n",#name);return 2;}
#define CALL(name, signature, ...) do { int rc=((int(*)signature)name)(__VA_ARGS__); if(rc){fprintf(stderr,"%s failed: %d\n",#name,rc);return 3;} } while(0)
int main(int argc,char **argv) {
    void *lib=dlopen("libcuda.so.1",RTLD_NOW);
    if(!lib){fprintf(stderr,"dlopen: %s\n",dlerror());return 1;}
    LOAD(cuInit);LOAD(cuDeviceGetCount);LOAD(cuDeviceGetName);LOAD(cuCtxCreate_v2);
    LOAD(cuModuleLoadData);LOAD(cuModuleGetFunction);LOAD(cuMemAlloc_v2);
    LOAD(cuMemcpyHtoD_v2);LOAD(cuMemcpyDtoH_v2);LOAD(cuLaunchKernel);LOAD(cuCtxSynchronize);
    LOAD(cuMemFree_v2);LOAD(cuCtxDestroy_v2);
    CALL(cuInit,(unsigned int),0);
    int count=0;CALL(cuDeviceGetCount,(int*),&count);
    if(count!=1){fprintf(stderr,"expected one assigned GPU, found %d\n",count);return 4;}
    char name[256];CALL(cuDeviceGetName,(char*,int,int),name,256,0);
    void *ctx,*module,*function;
    CALL(cuCtxCreate_v2,(void**,unsigned int,int),&ctx,0,0);
    const char *ptx=".version 7.0\n.target sm_80\n.address_size 64\n.visible .entry add7(.param .u64 data) { .reg .b64 %rd<4>; .reg .b32 %r<4>; ld.param.u64 %rd1,[data]; mov.u32 %r1,%tid.x; mul.wide.u32 %rd2,%r1,4; add.u64 %rd3,%rd1,%rd2; ld.global.u32 %r2,[%rd3]; add.u32 %r3,%r2,7; st.global.u32 [%rd3],%r3; ret; }";
    CALL(cuModuleLoadData,(void**,const void*),&module,ptx);
    CALL(cuModuleGetFunction,(void**,void*,const char*),&function,module,"add7");
    uint64_t ptr;unsigned int data[8];for(int i=0;i<8;i++)data[i]=i+10;
    CALL(cuMemAlloc_v2,(uint64_t*,size_t),&ptr,sizeof(data));
    CALL(cuMemcpyHtoD_v2,(uint64_t,const void*,size_t),ptr,data,sizeof(data));
    void *args[]={&ptr};
    CALL(cuLaunchKernel,(void*,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,void*,void**,void**),function,1,1,1,8,1,1,0,NULL,args,NULL);
    CALL(cuCtxSynchronize,(void));
    CALL(cuMemcpyDtoH_v2,(void*,uint64_t,size_t),data,ptr,sizeof(data));
    for(int i=0;i<8;i++)if(data[i]!=(unsigned)(i+17)){fprintf(stderr,"wrong result\n");return 5;}
    printf("CUDA kernel PASS: %s, visible=%d, result=%u..%u\n",name,count,data[0],data[7]);fflush(stdout);
    if(argc>1)sleep(atoi(argv[1]));
    CALL(cuMemFree_v2,(uint64_t),ptr);CALL(cuCtxDestroy_v2,(void*),ctx);return 0;
}
