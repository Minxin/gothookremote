LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := fakeputs
LOCAL_SRC_FILES := main.cpp

include $(BUILD_SHARED_LIBRARY)