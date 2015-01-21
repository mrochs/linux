###########################
#Linux module dev env stuff
###########################
export CONFIG_CFLSH=m
export MY_KERNEL_SRC=/kernel_src/linux-3.16.0

alias makemod='make -C $MY_KERNEL_SRC M=$(pwd)'
