#!/bin/bash

EYRIE_SOURCE_DIR=`dirname $0`
REQ_PLUGINS=${@:1}
OPTIONS_LOG=${EYRIE_SOURCE_DIR}/.options_log
BITS="64"

# Build known plugins
declare -A PLUGINS
PLUGINS[freemem]="-DUSE_FREEMEM "
PLUGINS[untrusted_io_syscall]="-DIO_SYSCALL_WRAPPING "
PLUGINS[linux_syscall]="-DLINUX_SYSCALL_WRAPPING "
PLUGINS[env_setup]="-DENV_SETUP "
PLUGINS[strace_debug]="-DINTERNAL_STRACE "
PLUGINS[paging]="-DUSE_PAGING -DUSE_FREEMEM "
PLUGINS[page_crypto]="-DPAGE_CRYPTO "
PLUGINS[page_hash]="-DUSE_PAGE_HASH "
PLUGINS[debug]="-DDEBUG "
PLUGINS[hpme]="-DUSE_HPME "
PLUGINS[sha3_rocc]="-DUSE_SHA3_ROCC "
PLUGINS[page_hash_bpt]="-DUSE_PAGE_HASH_BPT "
#PLUGINS[dynamic_resizing]="-DDYN_ALLOCATION "

OPTIONS_FLAGS=

echo > $OPTIONS_LOG

for plugin in $REQ_PLUGINS; do
    if [ $plugin == 'rv32' ]; then
	BITS="32"
    elif [[ ! ${PLUGINS[$plugin]+_} ]]; then
        echo "Unknown Eyrie plugin '$plugin'. Skipping"
    else
        OPTIONS_FLAGS+=${PLUGINS[$plugin]}
        echo -n "$plugin " >> $OPTIONS_LOG
    fi
done

export BITS
export OPTIONS_FLAGS
make -C $EYRIE_SOURCE_DIR clean
make -C $EYRIE_SOURCE_DIR
