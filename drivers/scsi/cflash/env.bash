###########################
#Linux module dev env stuff
###########################
export CONFIG_CFLASH=m
export MY_KERNEL_SRC=/kernel_src/linux-3.17.0

alias makemod='make -C $MY_KERNEL_SRC M=$(pwd)'
