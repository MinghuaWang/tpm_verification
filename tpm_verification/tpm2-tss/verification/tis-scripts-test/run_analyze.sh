TPM_PROJ_PATH=/home/trustinsoft/minghua_folder/tpm_project/tpm2-tss/
LIBGCRYPT_PATH=/home/trustinsoft/minghua_folder/tpm_project/libgcrypt-1.8.3/
LIBGPGERROR_PATH=/home/trustinsoft/minghua_folder/tpm_project/libgpg-error-1.32/

OPT=(
    -gui
    -slevel 10
    -val
    -address-alignment 16
    -unsafe-arrays
    -val-clone-on-recursive-calls
    -val-malloc-plevel 400
    -val-ptr-total-comparison
    -64
    -no-cxx-annot
    -no-cxx-precompile
    -no-cxx-runtime
    -no-val-print
    -no-val-show-initial-state
    -no-val-show-progress
    -val-slevel-merge-after-loop=@all
    -fclang-cpp-extra-args=-mno-sse
)

DEFINE=(
    -D GPGRT_ENABLE_ES_MACROS 
    -D HAVE_SYS_SELECT_H 
    -D MAXLOGLEVEL=LOGL_NONE 
)

SYSTEM_MODELIZATION=(
    /home/trustinsoft/tis/system_modelisation/gcc_builtins.c
    /home/trustinsoft/tis/system_modelisation/math.c 
    /home/trustinsoft/tis/system_modelisation/stdio.c
    /home/trustinsoft/tis/system_modelisation/stdlib.c 
    /home/trustinsoft/tis/system_modelisation/syscall.c
    /home/trustinsoft/tis/system_modelisation/threads.c
    /home/trustinsoft/tis/system_modelisation/time.c
    /home/trustinsoft/tis/system_modelisation/unistd.c
)

INCLUDE=(
    -I . 
    -I ${TPM_PROJ_PATH}/src/include/ 
    -I ${TPM_PROJ_PATH}/src/include/tss2/ 
    -I ${TPM_PROJ_PATH}/src/src/tss2-esys/ 
    -I ${TPM_PROJ_PATH}/src/src/tss2-sys/ 
    -I ${TPM_PROJ_PATH}/src/src/ 
    -I ${TPM_PROJ_PATH}/verification/necessary_files/ 
    -I ${TPM_PROJ_PATH}/verification/necessary_files/mpi/ 
    -I ${LIBGCRYPT_PATH}/src/ 
    -I ${LIBGPGERROR_PATH}/src/ 
    -I /home/trustinsoft/tis/includes 
)

LINK=(
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_crypto_gcrypt.c
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_context.c
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_crypto.c 
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_free.c 
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_iutil.c
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_mu.c
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_tcti_default.c 
    ${TPM_PROJ_PATH}/src/src/tss2-esys/esys_tr.c 
    ${TPM_PROJ_PATH}/src/src/tss2-esys/api/*.c 
    ${TPM_PROJ_PATH}/src/src/tss2-sys/api/*.c 
    ${TPM_PROJ_PATH}/src/src/tss2-sys/*.c 
    ${TPM_PROJ_PATH}/src/src/tss2-mu/*.c 
    ${LIBGCRYPT_PATH}/src/visibility.c 
    ${LIBGCRYPT_PATH}/cipher/md.c 
    ${LIBGCRYPT_PATH}/cipher/mac.c 
    ${LIBGCRYPT_PATH}/cipher/pubkey.c 
    ${LIBGCRYPT_PATH}/cipher/cipher.c 
    ${LIBGCRYPT_PATH}/cipher/primegen.c 
    ${LIBGCRYPT_PATH}/src/global.c 
    ${LIBGCRYPT_PATH}/src/stdmem.c 
    ${LIBGCRYPT_PATH}/src/secmem.c 
    ${LIBGCRYPT_PATH}/src/fips.c 
    ${LIBGCRYPT_PATH}/src/hwfeatures.c 
    ${LIBGCRYPT_PATH}/src/misc.c 
    ${LIBGCRYPT_PATH}/random/random-csprng.c 
    ${LIBGCRYPT_PATH}/mpi/mpiutil.c 
    ${LIBGCRYPT_PATH}/random/random.c 
    ${LIBGPGERROR_PATH}/src/visibility.c 
    ${LIBGPGERROR_PATH}/src/syscall-clamp.c 
    ${LIBGPGERROR_PATH}/src/posix-lock.c 
    ${LIBGPGERROR_PATH}/src/init.c 
    ${LIBGPGERROR_PATH}/src/estream.c 
)

RUNTIME=(
    /home/trustinsoft/tis/runtimes/libcxx-runtime.cpp
)

tis-analyzer++ "${OPT[@]}" "${DEFINE[@]}" "${INCLUDE[@]}" "${SYSTEM_MODELIZATION[@]}" "${LINK[@]}" $@

