LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := inject
LOCAL_SRC_FILES := toinject.cpp

include $(BUILD_EXECUTABLE)
#include $(BUILD_SHARED_LIBRARY)