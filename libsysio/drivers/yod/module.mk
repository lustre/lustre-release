if WITH_CPLANT_YOD
YOD_SRCS = drivers/yod/fs_yod.c
YOD_DRIVER_FLAGS = -DCPLANT_YOD
else
YOD_SRCS = 
YOD_DRIVER_FLAGS = 
endif

# Bring yod files along in the distribution regardless
YOD_EXTRA = include/cplant-yod.h drivers/yod/fs_yod.h drivers/yod/module.mk
